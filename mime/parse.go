package mime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	netmail "net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// Errors returned by the parser.
var (
	// ErrTooLarge reports a message, or decoded content, over Options.MaxSize.
	ErrTooLarge = errors.New("mime: message too large")
	// ErrTooDeep reports multipart nesting deeper than Options.MaxDepth.
	ErrTooDeep = errors.New("mime: multipart nesting too deep")
	// ErrTooManyParts reports more MIME parts than Options.MaxParts.
	ErrTooManyParts = errors.New("mime: too many MIME parts")
	// ErrNoHeader reports an input with no header field at all.
	ErrNoHeader = errors.New("mime: the input has no header field")
)

// Options bounds and tunes the parser. The zero value, and a nil *Options, use
// the defaults.
type Options struct {
	// MaxSize is the largest input and the largest decoded total accepted.
	// Default 64 MiB.
	MaxSize int
	// MaxDepth is the deepest multipart nesting. Default 20.
	MaxDepth int
	// MaxParts is the most MIME parts in one message. Default 2000.
	MaxParts int
	// MaxHeaders is the most fields read from one header block. Default 2000.
	MaxHeaders int
	// CharsetDecoder converts text in a charset the package does not read. It
	// returns the UTF-8 text and whether it understood the charset. A message
	// whose charset neither reads is decoded as UTF-8 with replacements and a
	// warning.
	CharsetDecoder func(charset string, b []byte) (string, bool)
}

func (o *Options) limits() Options {
	var out Options
	if o != nil {
		out = *o
	}
	if out.MaxSize <= 0 {
		out.MaxSize = 64 << 20
	}
	if out.MaxDepth <= 0 {
		out.MaxDepth = 20
	}
	if out.MaxParts <= 0 {
		out.MaxParts = 2000
	}
	if out.MaxHeaders <= 0 {
		out.MaxHeaders = 2000
	}
	return out
}

// Entity is one node of the MIME tree: a message, or a part of a multipart.
type Entity struct {
	// Header holds the fields of the entity.
	Header Header
	// MediaType is the lowercased "type/subtype", "text/plain" when absent.
	MediaType string
	// Params are the parameters of Content-Type, with lowercased names.
	Params map[string]string
	// Disposition is "attachment", "inline" or "", lowercased.
	Disposition string
	// DispositionParams are the parameters of Content-Disposition.
	DispositionParams map[string]string
	// Encoding is the lowercased Content-Transfer-Encoding, "7bit" when absent.
	Encoding string
	// Body is the content of a leaf with the transfer encoding removed. For an
	// identity encoding (7bit, 8bit, binary) it aliases the input. It is nil for
	// a multipart.
	Body []byte
	// Parts are the children of a multipart.
	Parts []*Entity
}

// Charset returns the charset parameter, lowercased, "" when absent.
func (e *Entity) Charset() string { return strings.ToLower(e.Params["charset"]) }

// IsMultipart reports whether the entity has children.
func (e *Entity) IsMultipart() bool { return strings.HasPrefix(e.MediaType, "multipart/") }

// Filename returns the file name from Content-Disposition, or from the name
// parameter of Content-Type.
func (e *Entity) Filename() string {
	if n := e.DispositionParams["filename"]; n != "" {
		return n
	}
	return e.Params["name"]
}

// ContentID returns the Content-ID without its angle brackets.
func (e *Entity) ContentID() string {
	id := strings.TrimSpace(e.Header.Get("Content-ID"))
	return strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
}

// Walk calls fn for the entity and for every descendant, depth first. A false
// return stops the walk.
func (e *Entity) Walk(fn func(*Entity) bool) bool {
	if !fn(e) {
		return false
	}
	for _, p := range e.Parts {
		if !p.Walk(fn) {
			return false
		}
	}
	return true
}

// Find returns the first entity, depth first, whose media type is mediaType.
func (e *Entity) Find(mediaType string) *Entity {
	var found *Entity
	e.Walk(func(x *Entity) bool {
		if x.MediaType == mediaType {
			found = x
			return false
		}
		return true
	})
	return found
}

// Text returns the body of a leaf as UTF-8 text in the charset of the part,
// with line breaks normalized to LF.
func (e *Entity) Text(opt *Options) (text string, warning string) {
	return decodeText(e.Body, e.Charset(), opt)
}

func decodeText(b []byte, charset string, opt *Options) (string, string) {
	s, ok := DecodeCharset(charset, b)
	warn := ""
	if !ok {
		if opt != nil && opt.CharsetDecoder != nil {
			if t, ok2 := opt.CharsetDecoder(charset, b); ok2 {
				s, ok = t, true
			}
		}
		if !ok {
			warn = "unknown charset " + charset + ": read as UTF-8"
		}
	}
	if strings.Contains(s, "\r\n") {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	return s, warn
}

// ParseEntity reads b as a message and returns its MIME tree.
func ParseEntity(b []byte, opt *Options) (*Entity, error) {
	o := opt.limits()
	if len(b) > o.MaxSize {
		return nil, ErrTooLarge
	}
	st := &parseState{opt: o}
	return st.entity(b, 0)
}

type parseState struct {
	opt   Options
	parts int
	size  int
}

func (st *parseState) entity(b []byte, depth int) (*Entity, error) {
	st.parts++
	if st.parts > st.opt.MaxParts {
		return nil, ErrTooManyParts
	}
	h, body := parseHeader(b, st.opt.MaxHeaders)
	e := &Entity{Header: h}
	ct := h.Get("Content-Type")
	if ct == "" {
		e.MediaType, e.Params = "text/plain", map[string]string{}
	} else {
		e.MediaType, e.Params = ParseMediaType(ct)
		if !strings.Contains(e.MediaType, "/") {
			e.MediaType = "text/plain"
		}
	}
	if cd := h.Get("Content-Disposition"); cd != "" {
		e.Disposition, e.DispositionParams = ParseMediaType(cd)
	}
	e.Encoding = strings.ToLower(strings.TrimSpace(stripComments(h.Get("Content-Transfer-Encoding"))))
	if e.Encoding == "" {
		e.Encoding = "7bit"
	}

	if strings.HasPrefix(e.MediaType, "multipart/") {
		boundary := e.Params["boundary"]
		if boundary != "" {
			if depth >= st.opt.MaxDepth {
				return nil, ErrTooDeep
			}
			for _, raw := range splitMultipart(body, boundary) {
				child, err := st.entity(raw, depth+1)
				if err != nil {
					return nil, err
				}
				e.Parts = append(e.Parts, child)
			}
			return e, nil
		}
		// A multipart with no boundary cannot be split: keep it as opaque text.
		e.MediaType = "text/plain"
	}

	decoded, err := st.decodeBody(body, e.Encoding)
	if err != nil {
		return nil, err
	}
	e.Body = decoded
	return e, nil
}

func (st *parseState) decodeBody(body []byte, enc string) ([]byte, error) {
	var out []byte
	switch enc {
	case "base64":
		out = decodeBase64(body)
	case "quoted-printable":
		out = decodeQuotedPrintable(body)
	default:
		out = body
	}
	st.size += len(out)
	if st.size > st.opt.MaxSize {
		return nil, ErrTooLarge
	}
	return out, nil
}

// splitMultipart cuts a multipart body into the raw bytes of its parts. It
// accepts bare LF line ends, white space after a delimiter, a missing closing
// delimiter, and ignores the preamble and the epilogue.
func splitMultipart(body []byte, boundary string) [][]byte {
	delim := []byte("--" + boundary)
	var parts [][]byte
	pos, partStart := 0, 0
	inPart := false
	for pos < len(body) {
		i := bytes.Index(body[pos:], delim)
		if i < 0 {
			break
		}
		i += pos
		if i > 0 && body[i-1] != '\n' {
			pos = i + 1
			continue
		}
		after := i + len(delim)
		closing := after+1 < len(body) && body[after] == '-' && body[after+1] == '-'
		eol := after
		if closing {
			eol += 2
		}
		for eol < len(body) && (body[eol] == ' ' || body[eol] == '\t') {
			eol++
		}
		if eol < len(body) && body[eol] != '\r' && body[eol] != '\n' {
			pos = i + 1
			continue
		}
		next := len(body)
		if nl := bytes.IndexByte(body[eol:], '\n'); nl >= 0 {
			next = eol + nl + 1
		}
		if inPart {
			end := i
			if end > partStart && body[end-1] == '\n' {
				end--
				if end > partStart && body[end-1] == '\r' {
					end--
				}
			}
			parts = append(parts, body[partStart:end])
		}
		if closing {
			return parts
		}
		partStart, inPart, pos = next, true, next
	}
	if inPart && partStart <= len(body) {
		parts = append(parts, body[partStart:])
	}
	return parts
}

// Message is a parsed e-mail: the fields most callers want, the headers in
// order and the MIME tree.
type Message struct {
	// Header holds every field of the message, in order.
	Header Header
	// From, To, Cc, Bcc and ReplyTo are the addresses of the fields. A group is
	// flattened to its members, and an item that is not an address is skipped
	// with a note in Warnings.
	From, To, Cc, Bcc, ReplyTo []Address
	// Subject is the decoded Subject.
	Subject string
	// Date is the Date field, zero when absent or unreadable.
	Date time.Time
	// MessageID is the Message-ID without angle brackets.
	MessageID string
	// Text and HTML are the bodies decoded to UTF-8 with LF line breaks. When a
	// message carries several text parts of one kind outside an alternative,
	// they are joined by a line break.
	Text, HTML string
	// Attachments are the parts that are not the text or HTML body.
	Attachments []Attachment
	// Root is the MIME tree.
	Root *Entity
	// Warnings describes what was read leniently or left undecoded.
	Warnings []string
}

// Parse reads an RFC 5322 message from r.
func Parse(r io.Reader, opt *Options) (*Message, error) {
	o := opt.limits()
	data, err := io.ReadAll(io.LimitReader(r, int64(o.MaxSize)+1))
	if err != nil {
		return nil, err
	}
	return ParseBytes(data, opt)
}

// ParseBytes reads an RFC 5322 message from b. The returned message may alias b.
func ParseBytes(b []byte, opt *Options) (*Message, error) {
	root, err := ParseEntity(b, opt)
	if err != nil {
		return nil, err
	}
	if root.Header.Len() == 0 {
		return nil, ErrNoHeader
	}
	m := &Message{Header: root.Header, Root: root}
	list := func(name string) []Address {
		var out []Address
		for _, v := range root.Header.Values(name) {
			if !utf8Valid(v) {
				v, _ = DecodeCharset("windows-1252", []byte(v))
			}
			got, problems := parseAddressListLenient(v)
			out = append(out, got...)
			for _, p := range problems {
				m.Warnings = append(m.Warnings, name+": "+p)
			}
		}
		return out
	}
	m.From, m.To, m.Cc, m.Bcc, m.ReplyTo = list("From"), list("To"), list("Cc"), list("Bcc"), list("Reply-To")
	m.Subject = root.Header.Text("Subject")
	if d := root.Header.Get("Date"); d != "" {
		if t, err := netmail.ParseDate(stripComments(d)); err == nil {
			m.Date = t
		} else {
			m.Warnings = append(m.Warnings, "Date: "+err.Error())
		}
	}
	id := strings.TrimSpace(root.Header.Get("Message-ID"))
	m.MessageID = strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
	m.collect(root, "", opt)
	return m, nil
}

func utf8Valid(s string) bool { return utf8.ValidString(s) }

// collect fills the bodies and the attachments from the tree.
func (m *Message) collect(e *Entity, parent string, opt *Options) {
	if e.IsMultipart() {
		sub := strings.TrimPrefix(e.MediaType, "multipart/")
		for _, p := range e.Parts {
			m.collect(p, sub, opt)
		}
		return
	}
	filename := e.Filename()
	isBody := (e.MediaType == "text/plain" || e.MediaType == "text/html") &&
		e.Disposition != "attachment" && filename == ""
	if !isBody {
		m.Attachments = append(m.Attachments, Attachment{
			Filename:    filename,
			ContentType: e.MediaType,
			Content:     e.Body,
			ContentID:   e.ContentID(),
			Inline:      e.Disposition == "inline",
		})
		return
	}
	s, warn := e.Text(opt)
	if warn != "" {
		m.Warnings = append(m.Warnings, warn)
	}
	target := &m.Text
	if e.MediaType == "text/html" {
		target = &m.HTML
	}
	switch {
	case *target == "":
		*target = s
	case parent != "alternative":
		*target += "\n" + s
	}
}

// String describes the message for logs, without its content.
func (m *Message) String() string {
	return fmt.Sprintf("message %q: %d from, %d to, %d attachments", m.MessageID, len(m.From), len(m.To), len(m.Attachments))
}
