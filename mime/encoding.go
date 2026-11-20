package mime

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const hexUpper = "0123456789ABCDEF"

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// ---- quoted-printable (RFC 2045 section 6.7) ----

// appendQuotedPrintable appends s encoded as quoted-printable text. Every line
// break in s (CRLF, LF or a bare CR) is written as CRLF, no encoded line is
// longer than 76 characters, and white space before a line break or at the end
// is encoded so that no gateway can strip it.
func appendQuotedPrintable(dst []byte, s string) []byte {
	col := 0
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\r' || c == '\n':
			i++
			if c == '\r' && i < len(s) && s[i] == '\n' {
				i++
			}
			dst = append(dst, '\r', '\n')
			col = 0
		case qpLiteral[c] || (c == ' ' || c == '\t') && i+1 < len(s) && s[i+1] != '\r' && s[i+1] != '\n':
			// A run of bytes that are written as themselves, up to the column
			// where the line has to be broken.
			room := 75 - col
			if room <= 0 {
				dst = append(dst, '=', '\r', '\n')
				col, room = 0, 75
			}
			j := i + 1
			limit := min(len(s), i+room)
			for j < limit {
				d := s[j]
				if qpLiteral[d] || (d == ' ' || d == '\t') && j+1 < len(s) && s[j+1] != '\r' && s[j+1] != '\n' {
					j++
					continue
				}
				break
			}
			dst = append(dst, s[i:j]...)
			col += j - i
			i = j
		default:
			if col+3 > 75 {
				dst = append(dst, '=', '\r', '\n')
				col = 0
			}
			dst = append(dst, '=', hexUpper[c>>4], hexUpper[c&15])
			col += 3
			i++
		}
	}
	return dst
}

// qpLiteral marks the bytes quoted-printable writes as themselves: printable
// ASCII except "=". White space is handled where its position is known.
var qpLiteral = func() (t [256]bool) {
	for c := 33; c <= 126; c++ {
		t[c] = c != '='
	}
	return
}()

// decodeQuotedPrintable decodes quoted-printable text leniently: an "=" that
// does not start an escape is kept, trailing white space before a line break
// is dropped, and a soft break may end in white space. Line breaks of the
// input are kept as they are.
func decodeQuotedPrintable(src []byte) []byte {
	dst := make([]byte, 0, len(src))
	for len(src) > 0 {
		line := src
		rest := []byte(nil)
		nl := 0
		if i := indexByte(src, '\n'); i >= 0 {
			line, rest = src[:i], src[i+1:]
			nl = 1
			if i > 0 && src[i-1] == '\r' {
				line = src[:i-1]
				nl = 2
			}
		}
		src = rest
		line = trimRightWSP(line)
		soft := false
		if n := len(line); n > 0 && line[n-1] == '=' {
			soft = true
			line = line[:n-1]
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if c == '=' && i+2 < len(line) {
				hi, ok1 := unhex(line[i+1])
				lo, ok2 := unhex(line[i+2])
				if ok1 && ok2 {
					dst = append(dst, hi<<4|lo)
					i += 2
					continue
				}
			}
			dst = append(dst, c)
		}
		if !soft && nl > 0 {
			if nl == 2 {
				dst = append(dst, '\r', '\n')
			} else {
				dst = append(dst, '\n')
			}
		}
	}
	return dst
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func trimRightWSP(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// ---- base64 (RFC 2045 section 6.8) ----

// appendBase64Lines appends src as base64 in lines of 76 characters, every
// line, the last one included, ending in CRLF. Nothing is appended for an
// empty src.
func appendBase64Lines(dst, src []byte) []byte {
	const raw = 57 // 57 bytes encode to 76 characters
	for len(src) > 0 {
		n := min(raw, len(src))
		start := len(dst)
		dst = growBy(dst, base64.StdEncoding.EncodedLen(n)+2)
		base64.StdEncoding.Encode(dst[start:], src[:n])
		dst = append(dst[:len(dst)-2], '\r', '\n')
		src = src[n:]
	}
	return dst
}

// growBy extends dst by n bytes, keeping its content.
func growBy(dst []byte, n int) []byte {
	if cap(dst)-len(dst) >= n {
		return dst[:len(dst)+n]
	}
	out := make([]byte, len(dst)+n, (len(dst)+n)*2)
	copy(out, dst)
	return out
}

// decodeBase64 decodes base64 leniently: characters outside the alphabet
// (white space, line breaks, stray bytes) are skipped, padding is optional and
// anything after the first padding run that is not padding is ignored.
func decodeBase64(src []byte) []byte {
	clean := make([]byte, 0, len(src))
	for _, c := range src {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			clean = append(clean, c)
		case c == '-':
			clean = append(clean, '+')
		case c == '_':
			clean = append(clean, '/')
		case c == '=':
			// Padding ends the data.
			return decodeBase64Clean(clean)
		}
	}
	return decodeBase64Clean(clean)
}

func decodeBase64Clean(clean []byte) []byte {
	// A single leftover character carries fewer than 8 bits and is dropped.
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
	n, _ := base64.RawStdEncoding.Decode(out, clean)
	return out[:n]
}

// ---- RFC 2047 encoded words ----

// DecodeWords decodes the RFC 2047 encoded words in an unstructured header
// value or a phrase. White space between two adjacent encoded words is
// dropped, an encoded word with an unknown encoding or invalid payload is left
// as written, and the result is valid UTF-8.
func DecodeWords(s string) string {
	if !strings.Contains(s, "=?") {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	prevEncoded := false
	pendingSpace := ""
	for len(s) > 0 {
		start := strings.Index(s, "=?")
		if start < 0 {
			sb.WriteString(pendingSpace)
			sb.WriteString(s)
			break
		}
		text, tail, ok := parseEncodedWord(s[start:])
		if !ok {
			sb.WriteString(pendingSpace)
			sb.WriteString(s[:start+2])
			pendingSpace = ""
			prevEncoded = false
			s = s[start+2:]
			continue
		}
		gap := s[:start]
		if prevEncoded && strings.TrimLeft(gap, " \t\r\n") == "" {
			// Folding white space between encoded words is not content.
			pendingSpace = ""
		} else {
			sb.WriteString(pendingSpace)
			sb.WriteString(gap)
			pendingSpace = ""
		}
		sb.WriteString(text)
		prevEncoded = true
		s = tail
	}
	return sb.String()
}

// parseEncodedWord decodes one "=?charset?enc?text?=" at the start of s.
func parseEncodedWord(s string) (text, rest string, ok bool) {
	// =?charset?E?payload?=
	body := s[2:]
	i := strings.IndexByte(body, '?')
	if i <= 0 {
		return "", "", false
	}
	charset := body[:i]
	if star := strings.IndexByte(charset, '*'); star >= 0 { // RFC 2231 language
		charset = charset[:star]
	}
	body = body[i+1:]
	if len(body) < 2 || body[1] != '?' {
		return "", "", false
	}
	enc := body[0]
	body = body[2:]
	end := strings.Index(body, "?=")
	if end < 0 {
		return "", "", false
	}
	payload := body[:end]
	if strings.ContainsAny(payload, " \t\r\n") || strings.ContainsAny(charset, " \t\r\n") {
		return "", "", false
	}
	var raw []byte
	switch enc {
	case 'B', 'b':
		raw = decodeBase64([]byte(payload))
	case 'Q', 'q':
		raw = decodeQ(payload)
	default:
		return "", "", false
	}
	text, _ = DecodeCharset(charset, raw)
	return text, body[end+2:], true
}

func decodeQ(p string) []byte {
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '_':
			out = append(out, ' ')
		case c == '=' && i+2 < len(p):
			hi, ok1 := unhex(p[i+1])
			lo, ok2 := unhex(p[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
			} else {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
	}
	return out
}

// qSafe reports whether c is written as itself inside an encoded word. The set
// is the one RFC 2047 allows in a phrase, which is also valid anywhere else.
func qSafe(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c == '!' || c == '*' || c == '+' || c == '-' || c == '/'
}

// needsWordEncoding reports whether a header text value has to travel as
// encoded words: it holds a non-ASCII or control character, white space that
// folding would alter, or text that would be read as an encoded word.
func needsWordEncoding(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == ' ' || s[len(s)-1] == ' ' || s[0] == '\t' || s[len(s)-1] == '\t' {
		return true
	}
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf || c < 0x20 || c == 0x7F {
			return true
		}
		if c == ' ' {
			if prevSpace {
				return true
			}
			prevSpace = true
		} else {
			prevSpace = false
		}
	}
	return strings.Contains(s, "=?")
}

// appendEncodedWords splits s into encoded words that fit the folder's line
// and writes them with the folding white space between them. The charset is
// UTF-8 and the encoding is the shorter of B and restricted Q.
func (f *folder) appendEncodedWords(s string) {
	useQ := qLength(s) <= base64.StdEncoding.EncodedLen(len(s))
	for len(s) > 0 {
		// An encoded word is at most 75 characters and the line stays within
		// 76: the word costs 12 characters of framing around its payload.
		sep := 0
		if f.sep {
			sep = 1
		}
		capacity := 76 - f.col - sep - 12
		if capacity < 12 {
			f.fold()
			capacity = 76 - f.col - 12
		}
		var n int
		if useQ {
			n = qPrefix(s, capacity)
		} else {
			n = bPrefix(s, capacity)
		}
		chunk := s[:n]
		s = s[n:]
		f.beginWord()
		start := len(f.dst)
		if useQ {
			f.dst = append(f.dst, "=?UTF-8?Q?"...)
			for i := 0; i < len(chunk); i++ {
				c := chunk[i]
				switch {
				case qSafe(c):
					f.dst = append(f.dst, c)
				case c == ' ':
					f.dst = append(f.dst, '_')
				default:
					f.dst = append(f.dst, '=', hexUpper[c>>4], hexUpper[c&15])
				}
			}
		} else {
			f.dst = append(f.dst, "=?UTF-8?B?"...)
			at := len(f.dst)
			f.dst = growBy(f.dst, base64.StdEncoding.EncodedLen(len(chunk)))
			base64.StdEncoding.Encode(f.dst[at:], []byte(chunk))
		}
		f.dst = append(f.dst, '?', '=')
		f.col += len(f.dst) - start
		f.sep = true
		f.first = false
		if len(s) > 0 {
			f.fold()
		}
	}
}

func qLength(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if qSafe(c) || c == ' ' {
			n++
		} else {
			n += 3
		}
	}
	return n
}

// qPrefix returns how many bytes of s, cut on a rune boundary, encode to at
// most capacity characters in Q. It always takes at least one rune.
func qPrefix(s string, capacity int) int {
	used, i := 0, 0
	for i < len(s) {
		size := 1
		if s[i] >= utf8.RuneSelf {
			_, size = utf8.DecodeRuneInString(s[i:])
		}
		cost := 0
		for j := i; j < i+size; j++ {
			if qSafe(s[j]) || s[j] == ' ' {
				cost++
			} else {
				cost += 3
			}
		}
		if used+cost > capacity && i > 0 {
			break
		}
		used += cost
		i += size
	}
	return i
}

// bPrefix returns how many bytes of s, cut on a rune boundary, encode to at
// most capacity characters in base64. It always takes at least one byte.
func bPrefix(s string, capacity int) int {
	maxBytes := max(capacity/4*3, 1)
	if maxBytes >= len(s) {
		return len(s)
	}
	n := maxBytes
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	if n == 0 {
		n = maxBytes
	}
	return n
}
