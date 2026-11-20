package mime

import (
	"strings"
	"unicode/utf8"
)

// Field is one header field: its name as written and its value unfolded, with
// the white space around it trimmed and no RFC 2047 decoding applied.
type Field struct {
	Name  string
	Value string
}

// Header is the ordered list of fields of a message or of one MIME part.
type Header struct {
	fields []Field
}

// NewHeader returns a Header holding the given fields in order.
func NewHeader(fields ...Field) Header { return Header{fields: fields} }

// Fields returns every field in the order of the message. The slice is shared.
func (h Header) Fields() []Field { return h.fields }

// Len returns the number of fields.
func (h Header) Len() int { return len(h.fields) }

// Get returns the value of the first field with the name, compared without
// regard to case, or "".
func (h Header) Get(name string) string {
	for i := range h.fields {
		if strings.EqualFold(h.fields[i].Name, name) {
			return h.fields[i].Value
		}
	}
	return ""
}

// Has reports whether a field with the name exists.
func (h Header) Has(name string) bool {
	for i := range h.fields {
		if strings.EqualFold(h.fields[i].Name, name) {
			return true
		}
	}
	return false
}

// Values returns the values of every field with the name, in order.
func (h Header) Values(name string) []string {
	var out []string
	for i := range h.fields {
		if strings.EqualFold(h.fields[i].Name, name) {
			out = append(out, h.fields[i].Value)
		}
	}
	return out
}

// Text returns the first value of the field as text: RFC 2047 encoded words
// decoded, and raw 8-bit bytes that are not UTF-8 read as Windows-1252.
func (h Header) Text(name string) string { return headerText(h.Get(name)) }

func headerText(v string) string {
	if v == "" {
		return ""
	}
	if !utf8.ValidString(v) {
		v, _ = DecodeCharset("windows-1252", []byte(v))
	}
	return strings.TrimSpace(DecodeWords(v))
}

// ParseHeader reads the header block at the start of b, which ends at the first
// empty line, and returns the fields and the bytes after that line. Lines end
// in CRLF or in a bare LF, a line starting with white space continues the
// previous field, and a line that is not a field is skipped. When b holds no
// empty line the whole input is the header and rest is empty.
func ParseHeader(b []byte) (h Header, rest []byte) {
	return parseHeader(b, 0)
}

func parseHeader(b []byte, maxFields int) (Header, []byte) {
	// Find the end of the header block.
	end, bodyStart := len(b), len(b)
	for pos := 0; pos < len(b); {
		nl := indexByte(b[pos:], '\n')
		lineEnd := len(b)
		next := len(b)
		if nl >= 0 {
			lineEnd = pos + nl
			next = lineEnd + 1
		}
		line := b[pos:lineEnd]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			end, bodyStart = pos, next
			break
		}
		pos = next
	}
	s := string(b[:end])

	var h Header
	var cur *Field
	var folded *strings.Builder
	flush := func() {
		if cur == nil {
			return
		}
		if folded != nil {
			cur.Value = strings.TrimRight(folded.String(), " \t")
			folded = nil
		} else {
			cur.Value = strings.TrimRight(cur.Value, " \t")
		}
		cur = nil
	}
	for pos := 0; pos < len(s); {
		nl := strings.IndexByte(s[pos:], '\n')
		lineEnd, next := len(s), len(s)
		if nl >= 0 {
			lineEnd = pos + nl
			next = lineEnd + 1
		}
		line := s[pos:lineEnd]
		pos = next
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if cur == nil {
				continue
			}
			if folded == nil {
				folded = &strings.Builder{}
				folded.WriteString(cur.Value)
			}
			folded.WriteString(line)
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimRight(line[:colon], " \t")
		if !validFieldName(name) {
			continue
		}
		if maxFields > 0 && len(h.fields) >= maxFields {
			break
		}
		h.fields = append(h.fields, Field{Name: name, Value: strings.TrimLeft(line[colon+1:], " \t")})
		cur = &h.fields[len(h.fields)-1]
	}
	flush()
	return h, b[bodyStart:]
}

func validFieldName(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= 32 || c >= 127 {
			return false
		}
	}
	return s != ""
}

// ParseHeaderBlocks reads consecutive header blocks separated by empty lines,
// as in the body of a message/delivery-status or message/feedback-report part.
// Blocks with no field are skipped.
func ParseHeaderBlocks(b []byte) []Header {
	var out []Header
	for len(b) > 0 {
		h, rest := ParseHeader(b)
		if h.Len() > 0 {
			out = append(out, h)
		}
		if len(rest) == len(b) { // no progress
			break
		}
		b = rest
	}
	return out
}
