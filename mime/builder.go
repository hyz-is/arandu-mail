package mime

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Errors returned by Build.
var (
	// ErrNoFrom reports a message with no From address.
	ErrNoFrom = errors.New("mime: the message has no From address")
	// ErrHeaderInjection reports a CR, LF or NUL inside a value that would be
	// written to a header or to a MIME parameter.
	ErrHeaderInjection = errors.New("mime: a header value holds a CR, LF or NUL")
	// ErrInvalidHeaderName reports a header name that is not a valid field name.
	ErrInvalidHeaderName = errors.New("mime: invalid header name")
	// ErrReservedHeader reports a custom header that the builder writes itself.
	ErrReservedHeader = errors.New("mime: the builder writes this header itself")
	// ErrLineTooLong reports a single token that cannot be kept within the
	// 998-octet line limit because it has nowhere to be folded.
	ErrLineTooLong = errors.New("mime: a header token is longer than 998 octets")
	// ErrInvalidContentType reports a Content-Type that is not "type/subtype".
	ErrInvalidContentType = errors.New("mime: invalid content type")
	// ErrInvalidContentID reports a Content-ID with characters a msg-id cannot hold.
	ErrInvalidContentID = errors.New("mime: invalid content id")
	// ErrInvalidUnsubscribe reports a List-Unsubscribe target that is not an
	// http, https or mailto URI, or a one-click request without an https one.
	ErrInvalidUnsubscribe = errors.New("mime: invalid list-unsubscribe")
)

// Attachment is a file added to a message.
type Attachment struct {
	// Filename is shown to the reader. It may be non-ASCII.
	Filename string
	// ContentType is the media type. When empty it is taken from the file
	// extension, and falls back to application/octet-stream.
	ContentType string
	// Content is the file.
	Content []byte
	// ContentID makes the attachment an inline part the HTML refers to as
	// "cid:<ContentID>". Give it without angle brackets.
	ContentID string
	// Inline is set by Parse for a part whose disposition is inline. Build
	// ignores it: a ContentID is what makes a part inline.
	Inline bool
}

// Header is a name and a value of a custom header.
type headerField struct{ name, value string }

// Builder assembles a message. The setters return the builder so calls chain,
// and the first error is kept and returned by Build.
//
// A Builder is not safe for concurrent use. Reset makes it reusable and keeps
// its slices.
type Builder struct {
	from      []Address
	to        []Address
	cc        []Address
	bcc       []Address
	replyTo   []Address
	subject   string
	text      string
	html      string
	atts      []Attachment
	headers   []headerField
	messageID string
	date      time.Time
	unsub     []string
	oneClick  bool
	smtputf8  bool
	err       error
}

// NewBuilder returns an empty Builder.
func NewBuilder() *Builder { return &Builder{} }

// Reset clears the builder for reuse.
func (b *Builder) Reset() {
	*b = Builder{
		from: b.from[:0], to: b.to[:0], cc: b.cc[:0], bcc: b.bcc[:0], replyTo: b.replyTo[:0],
		atts: b.atts[:0], headers: b.headers[:0], unsub: b.unsub[:0],
	}
}

func (b *Builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

func (b *Builder) addrs(dst []Address, field string, list []string) []Address {
	for _, s := range list {
		if err := checkText(field, s); err != nil {
			b.fail(err)
			continue
		}
		parsed, err := ParseAddressList(s)
		if err != nil {
			b.fail(fmt.Errorf("%s: %w", field, err))
			continue
		}
		dst = append(dst, parsed...)
	}
	return dst
}

// From sets the sender, "Name <addr>" or "addr".
func (b *Builder) From(addr string) *Builder {
	b.from = b.addrs(b.from[:0], "From", []string{addr})
	return b
}

// FromAddress sets the sender from an Address.
func (b *Builder) FromAddress(a Address) *Builder {
	b.checkAddresses("From", a)
	b.from = append(b.from[:0], a)
	return b
}

func (b *Builder) checkAddresses(field string, list ...Address) {
	for _, a := range list {
		if err := checkText(field, a.Name+a.Address); err != nil {
			b.fail(err)
		}
		if !strings.Contains(a.Address, "@") {
			b.fail(fmt.Errorf("%s: %w: %q", field, ErrInvalidAddress, a.Address))
		}
	}
}

// To adds recipients. Each argument may itself be a comma separated list.
func (b *Builder) To(addrs ...string) *Builder { b.to = b.addrs(b.to, "To", addrs); return b }

// Cc adds carbon-copy recipients.
func (b *Builder) Cc(addrs ...string) *Builder { b.cc = b.addrs(b.cc, "Cc", addrs); return b }

// Bcc adds blind recipients. They are part of Recipients and never written to
// a header.
func (b *Builder) Bcc(addrs ...string) *Builder { b.bcc = b.addrs(b.bcc, "Bcc", addrs); return b }

// ReplyTo adds Reply-To addresses.
func (b *Builder) ReplyTo(addrs ...string) *Builder {
	b.replyTo = b.addrs(b.replyTo, "Reply-To", addrs)
	return b
}

// ToAddresses adds recipients that are already parsed.
func (b *Builder) ToAddresses(a ...Address) *Builder {
	b.checkAddresses("To", a...)
	b.to = append(b.to, a...)
	return b
}

// CcAddresses adds carbon-copy recipients that are already parsed.
func (b *Builder) CcAddresses(a ...Address) *Builder {
	b.checkAddresses("Cc", a...)
	b.cc = append(b.cc, a...)
	return b
}

// BccAddresses adds blind recipients that are already parsed.
func (b *Builder) BccAddresses(a ...Address) *Builder {
	b.checkAddresses("Bcc", a...)
	b.bcc = append(b.bcc, a...)
	return b
}

// Subject sets the subject. It may be non-ASCII.
func (b *Builder) Subject(s string) *Builder {
	if err := checkText("Subject", s); err != nil {
		b.fail(err)
	}
	b.subject = s
	return b
}

// Text sets the plain-text body.
func (b *Builder) Text(s string) *Builder { b.text = s; return b }

// HTML sets the HTML body.
func (b *Builder) HTML(s string) *Builder { b.html = s; return b }

// Attach adds a file. An attachment with a ContentID is an inline image of the
// HTML body.
func (b *Builder) Attach(a Attachment) *Builder {
	if a.ContentType != "" && !validContentType(a.ContentType) {
		b.fail(fmt.Errorf("%w: %q", ErrInvalidContentType, a.ContentType))
		return b
	}
	if err := checkText("attachment filename", a.Filename); err != nil {
		b.fail(err)
		return b
	}
	if a.ContentID != "" && !validContentID(a.ContentID) {
		b.fail(fmt.Errorf("%w: %q", ErrInvalidContentID, a.ContentID))
		return b
	}
	b.atts = append(b.atts, a)
	return b
}

// Header adds a custom header. The headers the builder writes itself (From,
// To, Cc, Bcc, Reply-To, Subject, Date, Message-ID, MIME-Version and the
// Content-* family) are refused.
func (b *Builder) Header(name, value string) *Builder {
	if !validHeaderName(name) {
		b.fail(fmt.Errorf("%w: %q", ErrInvalidHeaderName, name))
		return b
	}
	if err := checkText(name, value); err != nil {
		b.fail(err)
		return b
	}
	lower := strings.ToLower(name)
	switch lower {
	case "from", "to", "cc", "bcc", "reply-to", "subject", "date", "message-id", "mime-version":
		b.fail(fmt.Errorf("%w: %s", ErrReservedHeader, name))
		return b
	}
	if strings.HasPrefix(lower, "content-") {
		b.fail(fmt.Errorf("%w: %s", ErrReservedHeader, name))
		return b
	}
	b.headers = append(b.headers, headerField{name, value})
	return b
}

// MessageID sets the Message-ID, with or without angle brackets. Without a
// call, Build generates one on the domain of the From address.
func (b *Builder) MessageID(id string) *Builder {
	id = strings.TrimSuffix(strings.TrimPrefix(id, "<"), ">")
	if !validContentID(id) {
		b.fail(fmt.Errorf("%w: message id %q", ErrInvalidContentID, id))
		return b
	}
	b.messageID = id
	return b
}

// Date sets the Date header. Without a call, Build uses the current time.
func (b *Builder) Date(t time.Time) *Builder { b.date = t; return b }

// ListUnsubscribe sets the List-Unsubscribe header (RFC 2369) from http, https
// and mailto URIs.
func (b *Builder) ListUnsubscribe(uris ...string) *Builder {
	for _, u := range uris {
		if err := checkText("List-Unsubscribe", u); err != nil {
			b.fail(err)
			return b
		}
		if !validUnsubscribeURI(u) {
			b.fail(fmt.Errorf("%w: %q", ErrInvalidUnsubscribe, u))
			return b
		}
	}
	b.unsub = append(b.unsub, uris...)
	return b
}

// OneClickUnsubscribe adds List-Unsubscribe-Post: List-Unsubscribe=One-Click
// (RFC 8058). It needs at least one https URI in ListUnsubscribe, and the
// message has to be DKIM-signed over both headers to be honoured.
func (b *Builder) OneClickUnsubscribe() *Builder { b.oneClick = true; return b }

// SMTPUTF8 allows addresses with a non-ASCII local part (RFC 6532), kept as
// UTF-8 in the headers. Without it such an address makes Build fail with
// ErrNeedsSMTPUTF8, and a non-ASCII domain is written as Punycode.
func (b *Builder) SMTPUTF8(on bool) *Builder { b.smtputf8 = on; return b }

// NeedsSMTPUTF8 reports whether the message holds an address that can only be
// delivered over a session that offers SMTPUTF8.
func (b *Builder) NeedsSMTPUTF8() bool {
	for _, list := range [][]Address{b.from, b.to, b.cc, b.bcc, b.replyTo} {
		for _, a := range list {
			if !isASCII(a.Local()) {
				return true
			}
		}
	}
	return false
}

// Recipients returns the envelope recipients: To, Cc and Bcc, in that order,
// with the domains in ASCII form.
func (b *Builder) Recipients() ([]string, error) {
	out := make([]string, 0, len(b.to)+len(b.cc)+len(b.bcc))
	for _, list := range [][]Address{b.to, b.cc, b.bcc} {
		for _, a := range list {
			e, err := a.Envelope(b.smtputf8)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// ID returns the Message-ID of the message, without angle brackets,
// generating and keeping one if none was set.
func (b *Builder) ID() string {
	if b.messageID == "" {
		b.messageID = newMessageID(b.fromDomain())
	}
	return b.messageID
}

func (b *Builder) fromDomain() string {
	if len(b.from) > 0 {
		if d := b.from[0].ASCIIDomain(); d != "" {
			return d
		}
	}
	return "localhost"
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// Build returns the message.
func (b *Builder) Build() ([]byte, error) {
	return b.AppendTo(make([]byte, 0, b.sizeHint()))
}

// WriteTo writes the message to w. It builds into a pooled buffer, so a caller
// that streams many messages does not allocate one buffer per message.
func (b *Builder) WriteTo(w io.Writer) (int64, error) {
	bp := bufPool.Get().(*[]byte)
	buf, err := b.AppendTo((*bp)[:0])
	if err != nil {
		bufPool.Put(bp)
		return 0, err
	}
	n, werr := w.Write(buf)
	if cap(buf) <= 4<<20 {
		*bp = buf[:0]
		bufPool.Put(bp)
	}
	return int64(n), werr
}

var bufPool = sync.Pool{New: func() any { s := make([]byte, 0, 16<<10); return &s }}

func (b *Builder) sizeHint() int {
	n := 1024 + len(b.text) + len(b.html) + len(b.text)/2 + len(b.html)/2
	for _, a := range b.atts {
		n += len(a.Content)*4/3 + len(a.Content)/57*2 + 300
	}
	return n
}

// AppendTo appends the message to dst and returns the extended slice.
func (b *Builder) AppendTo(dst []byte) ([]byte, error) {
	if b.err != nil {
		return dst, b.err
	}
	if len(b.from) == 0 {
		return dst, ErrNoFrom
	}
	if len(b.from) > 1 {
		return dst, fmt.Errorf("mime: %d From addresses; set one", len(b.from))
	}
	for _, list := range [][]Address{b.from, b.to, b.cc, b.bcc, b.replyTo} {
		for _, a := range list {
			if !b.smtputf8 && !isASCII(a.Local()) {
				return dst, fmt.Errorf("%w: %s", ErrNeedsSMTPUTF8, a.Address)
			}
		}
	}
	if len(b.unsub) == 0 && b.oneClick {
		return dst, fmt.Errorf("%w: one-click needs a URI", ErrInvalidUnsubscribe)
	}
	if b.oneClick {
		https := false
		for _, u := range b.unsub {
			if strings.HasPrefix(strings.ToLower(u), "https://") {
				https = true
			}
		}
		if !https {
			return dst, fmt.Errorf("%w: one-click needs an https URI", ErrInvalidUnsubscribe)
		}
	}
	if len(b.unsub) > 0 {
		for _, h := range b.headers {
			if l := strings.ToLower(h.name); l == "list-unsubscribe" || l == "list-unsubscribe-post" {
				return dst, fmt.Errorf("%w: %s is set through ListUnsubscribe", ErrReservedHeader, h.name)
			}
		}
	}

	plan := b.plan()
	start := len(dst)
	f := folder{dst: dst}

	date := b.date
	if date.IsZero() {
		date = time.Now()
	}
	f.dst = append(f.dst, "Date: "...)
	f.dst = date.AppendFormat(f.dst, time.RFC1123Z)
	f.finish()

	f.start("From")
	f.appendAddressList(b.from, b.smtputf8)
	f.finish()
	if len(b.to) > 0 {
		f.start("To")
		f.appendAddressList(b.to, b.smtputf8)
		f.finish()
	}
	if len(b.cc) > 0 {
		f.start("Cc")
		f.appendAddressList(b.cc, b.smtputf8)
		f.finish()
	}
	if len(b.replyTo) > 0 {
		f.start("Reply-To")
		f.appendAddressList(b.replyTo, b.smtputf8)
		f.finish()
	}
	f.start("Subject")
	f.text(sanitizeUTF8(b.subject))
	f.finish()
	f.start("Message-ID")
	f.word("<" + b.ID() + ">")
	f.finish()
	f.start("MIME-Version")
	f.word("1.0")
	f.finish()
	for _, h := range b.headers {
		f.start(h.name)
		f.text(sanitizeUTF8(h.value))
		f.finish()
	}
	if len(b.unsub) > 0 {
		f.start("List-Unsubscribe")
		for i, u := range b.unsub {
			f.word("<" + u + ">")
			if i < len(b.unsub)-1 {
				f.glue(",")
			}
		}
		f.finish()
		if b.oneClick {
			f.start("List-Unsubscribe-Post")
			f.word("List-Unsubscribe=One-Click")
			f.finish()
		}
	}
	dst = f.dst
	headerEnd := len(dst)

	// A token that could not be folded is the only way to pass the line limit,
	// and it is the caller's input.
	if err := checkLines(dst[start:headerEnd]); err != nil {
		return dst[:start], err
	}
	return b.appendBody(dst, plan), nil
}

// checkLines fails when a line of the header block, or of a 7-bit body, is
// longer than the RFC limit.
func checkLines(msg []byte) error {
	line := 0
	for _, c := range msg {
		if c == '\n' {
			line = 0
			continue
		}
		line++
		if line > maxLine+1 { // +1 for the CR
			return ErrLineTooLong
		}
	}
	return nil
}

// ---- structure ----

type plan struct {
	text, html       string
	hasText, hasHTML bool
	textEnc, htmlEnc transferEncoding
	inline           []int // attachments referenced by the HTML (multipart/related)
	files            []int // attachments listed in multipart/mixed
	mixed, alt, rel  string
}

func (b *Builder) plan() *plan {
	p := &plan{text: b.text, html: b.html, hasText: b.text != "", hasHTML: b.html != ""}
	if p.hasText {
		p.textEnc = chooseEncoding(b.text)
	}
	if p.hasHTML {
		p.htmlEnc = chooseEncoding(b.html)
	}
	for i, a := range b.atts {
		if a.ContentID != "" && p.hasHTML {
			p.inline = append(p.inline, i)
		} else {
			p.files = append(p.files, i)
		}
	}
	if len(p.files) > 0 {
		p.mixed = newBoundary()
	}
	if p.hasText && p.hasHTML {
		p.alt = newBoundary()
	}
	if len(p.inline) > 0 {
		p.rel = newBoundary()
	}
	// A boundary must not occur inside a body that is written as is. Every
	// boundary starts with the same marker, so one scan of each body clears them.
	marked := strings.Contains(p.text, "arandu_") || strings.Contains(p.html, "arandu_")
	for retry := 0; marked && retry < 4; retry++ {
		clash := false
		for _, bd := range [...]string{p.mixed, p.alt, p.rel} {
			if bd == "" {
				continue
			}
			if p.textEnc != encBase64 && strings.Contains(p.text, bd) || p.htmlEnc != encBase64 && strings.Contains(p.html, bd) {
				clash = true
			}
		}
		if !clash {
			break
		}
		if p.mixed != "" {
			p.mixed = newBoundary()
		}
		if p.alt != "" {
			p.alt = newBoundary()
		}
		if p.rel != "" {
			p.rel = newBoundary()
		}
	}
	return p
}

func newBoundary() string {
	var buf [7 + 32]byte
	copy(buf[:], "arandu_")
	hex16(buf[7:23], rand.Uint64())
	hex16(buf[23:], rand.Uint64())
	return string(buf[:])
}

func hex16(dst []byte, v uint64) {
	for i := 15; i >= 0; i-- {
		dst[i] = "0123456789abcdef"[v&15]
		v >>= 4
	}
}

func newMessageID(domain string) string {
	var buf [64]byte
	n := copy(buf[:], strconv.AppendInt(buf[:0], time.Now().UnixNano(), 36))
	buf[n] = '.'
	n++
	hex16(buf[n:n+16], rand.Uint64())
	n += 16
	buf[n] = '@'
	n++
	return string(buf[:n]) + domain
}

func (b *Builder) appendBody(dst []byte, p *plan) []byte {
	if p.mixed != "" {
		dst = appendMultipartHeader(dst, "mixed", p.mixed)
		dst = append(dst, "--"...)
		dst = append(dst, p.mixed...)
		dst = append(dst, '\r', '\n')
		if p.hasText || p.hasHTML {
			dst = b.appendAlternative(dst, p)
		} else {
			// Only files: an empty text part keeps the message well formed.
			dst = appendLeaf(dst, "text/plain", encSevenBit, "")
		}
		for _, i := range p.files {
			dst = append(dst, "--"...)
			dst = append(dst, p.mixed...)
			dst = append(dst, '\r', '\n')
			dst = b.appendAttachment(dst, &b.atts[i])
		}
		dst = append(dst, "--"...)
		dst = append(dst, p.mixed...)
		dst = append(dst, '-', '-', '\r', '\n')
		return dst
	}
	if p.hasText || p.hasHTML {
		return b.appendAlternative(dst, p)
	}
	return appendLeaf(dst, "text/plain", encSevenBit, "")
}

func (b *Builder) appendAlternative(dst []byte, p *plan) []byte {
	if p.alt == "" {
		if p.hasHTML {
			return b.appendRelated(dst, p)
		}
		return appendLeaf(dst, "text/plain", p.textEnc, p.text)
	}
	dst = appendMultipartHeader(dst, "alternative", p.alt)
	dst = append(dst, "--"...)
	dst = append(dst, p.alt...)
	dst = append(dst, '\r', '\n')
	dst = appendLeaf(dst, "text/plain", p.textEnc, p.text)
	dst = append(dst, "--"...)
	dst = append(dst, p.alt...)
	dst = append(dst, '\r', '\n')
	dst = b.appendRelated(dst, p)
	dst = append(dst, "--"...)
	dst = append(dst, p.alt...)
	dst = append(dst, '-', '-', '\r', '\n')
	return dst
}

func (b *Builder) appendRelated(dst []byte, p *plan) []byte {
	if p.rel == "" {
		return appendLeaf(dst, "text/html", p.htmlEnc, p.html)
	}
	dst = appendMultipartHeader(dst, "related", p.rel)
	dst = append(dst, "--"...)
	dst = append(dst, p.rel...)
	dst = append(dst, '\r', '\n')
	dst = appendLeaf(dst, "text/html", p.htmlEnc, p.html)
	for _, i := range p.inline {
		dst = append(dst, "--"...)
		dst = append(dst, p.rel...)
		dst = append(dst, '\r', '\n')
		dst = b.appendAttachment(dst, &b.atts[i])
	}
	dst = append(dst, "--"...)
	dst = append(dst, p.rel...)
	dst = append(dst, '-', '-', '\r', '\n')
	return dst
}

func appendMultipartHeader(dst []byte, subtype, boundary string) []byte {
	f := folder{dst: dst}
	f.start("Content-Type")
	f.word("multipart/" + subtype)
	f.appendParam("boundary", boundary)
	f.finish()
	f.dst = append(f.dst, '\r', '\n')
	return f.dst
}

// appendLeaf writes a text part: its headers, a blank line and the encoded
// body, the last line ended so a delimiter can follow.
func appendLeaf(dst []byte, mediaType string, enc transferEncoding, body string) []byte {
	dst = append(dst, "Content-Type: "...)
	dst = append(dst, mediaType...)
	dst = append(dst, "; charset=utf-8\r\nContent-Transfer-Encoding: "...)
	dst = append(dst, enc.String()...)
	dst = append(dst, '\r', '\n', '\r', '\n')
	switch enc {
	case encBase64:
		dst = appendBase64Text(dst, body)
		if len(body) == 0 {
			dst = append(dst, '\r', '\n')
		}
	case encQuotedPrintable:
		dst = appendQuotedPrintable(dst, body)
		dst = append(dst, '\r', '\n')
	default:
		dst = appendCRLFText(dst, body)
		dst = append(dst, '\r', '\n')
	}
	return dst
}

// appendCRLFText appends s with every line break written as CRLF.
func appendCRLFText(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			dst = append(dst, '\r', '\n')
		case '\n':
			dst = append(dst, '\r', '\n')
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

// appendBase64Text appends text as base64 after normalizing line breaks.
func appendBase64Text(dst []byte, s string) []byte {
	if !strings.ContainsAny(s, "\r\n") || !needsLineNormalization(s) {
		bp := bufPool.Get().(*[]byte)
		buf := append((*bp)[:0], s...)
		dst = appendBase64Lines(dst, buf)
		*bp = buf[:0]
		bufPool.Put(bp)
		return dst
	}
	bp := bufPool.Get().(*[]byte)
	buf := appendCRLFText((*bp)[:0], s)
	dst = appendBase64Lines(dst, buf)
	if cap(buf) <= 4<<20 {
		*bp = buf[:0]
		bufPool.Put(bp)
	}
	return dst
}

func needsLineNormalization(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			if i == 0 || s[i-1] != '\r' {
				return true
			}
		case '\r':
			if i+1 >= len(s) || s[i+1] != '\n' {
				return true
			}
		}
	}
	return false
}

func (b *Builder) appendAttachment(dst []byte, a *Attachment) []byte {
	ct := a.ContentType
	if ct == "" {
		ct = guessContentType(a.Filename)
	}
	f := folder{dst: dst}
	f.start("Content-Type")
	f.word(ct)
	if a.Filename != "" {
		f.appendParam("name", a.Filename)
	}
	f.finish()
	f.start("Content-Transfer-Encoding")
	f.word("base64")
	f.finish()
	if a.ContentID != "" {
		f.start("Content-ID")
		f.word("<" + a.ContentID + ">")
		f.finish()
		f.start("Content-Disposition")
		f.word("inline")
	} else {
		f.start("Content-Disposition")
		f.word("attachment")
	}
	if a.Filename != "" {
		f.appendParam("filename", a.Filename)
	}
	f.finish()
	f.dst = append(f.dst, '\r', '\n')
	dst = appendBase64Lines(f.dst, a.Content)
	if len(a.Content) == 0 {
		dst = append(dst, '\r', '\n')
	}
	return dst
}

// ---- transfer encoding choice ----

type transferEncoding uint8

const (
	encSevenBit transferEncoding = iota
	encQuotedPrintable
	encBase64
)

func (e transferEncoding) String() string {
	switch e {
	case encQuotedPrintable:
		return "quoted-printable"
	case encBase64:
		return "base64"
	}
	return "7bit"
}

// chooseEncoding picks the transfer encoding of a text body: 7bit when the text
// is plain ASCII with lines that are short enough and end in a visible
// character, otherwise quoted-printable, or base64 when most bytes would need
// escaping.
func chooseEncoding(s string) transferEncoding {
	nonASCII, longest, line := 0, 0, 0
	trailingWSP := false
	var prev byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch scanClass[c] {
		case classPlain:
			line++
		case classBad:
			nonASCII++
			line++
		case classBreak:
			if line > longest {
				longest = line
			}
			if prev == ' ' || prev == '\t' {
				trailingWSP = true
			}
			line = 0
		case classSpace:
			line++
		}
		prev = c
	}
	if line > longest {
		longest = line
	}
	if prev == ' ' || prev == '\t' {
		trailingWSP = true
	}
	if nonASCII == 0 && longest <= maxLine && !trailingWSP {
		return encSevenBit
	}
	// Quoted-printable stays readable and costs at most 1.5 times the text while
	// a quarter of the bytes or fewer are escaped; past that base64 is smaller.
	if nonASCII*4 <= len(s) {
		return encQuotedPrintable
	}
	return encBase64
}

const (
	classPlain = iota
	classBad
	classBreak
	classSpace
)

// scanClass sorts every byte for chooseEncoding: printable ASCII, a byte that
// needs escaping, a line break, or white space.
var scanClass = func() (t [256]uint8) {
	for c := 0; c < 256; c++ {
		switch {
		case c == '\r' || c == '\n':
			t[c] = classBreak
		case c == ' ' || c == '\t':
			t[c] = classSpace
		case c < 0x20 || c >= 0x7F:
			t[c] = classBad
		}
	}
	return
}()

// ---- validation ----

// checkText rejects a value that would end a header line or hold a NUL.
func checkText(field, s string) error {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\r' || c == '\n' || c == 0 {
			return fmt.Errorf("%w in %s", ErrHeaderInjection, field)
		}
	}
	return nil
}

func validHeaderName(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 32 || c >= 127 || c == ':' {
			return false
		}
	}
	return true
}

func validContentType(s string) bool {
	typ, sub, ok := strings.Cut(s, "/")
	return ok && isToken(typ) && isToken(sub) && !strings.Contains(sub, "/")
}

// validContentID reports whether s can sit inside the angle brackets of a
// msg-id: no white space, no angle brackets, no control characters.
func validContentID(s string) bool {
	if s == "" || len(s) > 500 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7F || c == '<' || c == '>' || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func validUnsubscribeURI(u string) bool {
	l := strings.ToLower(u)
	if !strings.HasPrefix(l, "https://") && !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "mailto:") {
		return false
	}
	for i := 0; i < len(u); i++ {
		if c := u[i]; c <= ' ' || c >= 0x7F || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

var extTypes = map[string]string{
	".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml", ".txt": "text/plain",
	".html": "text/html", ".htm": "text/html", ".csv": "text/csv", ".ics": "text/calendar",
	".json": "application/json", ".xml": "application/xml", ".zip": "application/zip",
	".gz": "application/gzip", ".doc": "application/msword",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xls":  "application/vnd.ms-excel",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".ppt":  "application/vnd.ms-powerpoint",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".mp3":  "audio/mpeg", ".mp4": "video/mp4", ".eml": "message/rfc822",
}

func guessContentType(filename string) string {
	if i := strings.LastIndexByte(filename, '.'); i >= 0 {
		if t, ok := extTypes[strings.ToLower(filename[i:])]; ok {
			return t
		}
	}
	return "application/octet-stream"
}
