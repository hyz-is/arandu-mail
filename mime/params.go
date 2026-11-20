package mime

import (
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseMediaType parses a Content-Type or Content-Disposition value such as
// `multipart/mixed; boundary="x"` into its lowercased type and its parameters.
//
// It is lenient the way mail readers are: an unquoted value may hold spaces and
// UTF-8, a parameter without a value is skipped, a quoted value may be left
// unterminated, RFC 2231 continuations and charset extensions
// (`filename*0*=utf-8”%C3%A9`) are joined and decoded, and RFC 2047 encoded
// words in a value are decoded. Parameter names are lowercased; when a name
// repeats, the first wins.
func ParseMediaType(v string) (mediaType string, params map[string]string) {
	typ, rest, _ := strings.Cut(v, ";")
	mediaType = strings.ToLower(strings.TrimSpace(stripComments(typ)))
	params = map[string]string{}
	if strings.TrimSpace(rest) == "" {
		return mediaType, params
	}

	type piece struct {
		index   int
		value   string
		encoded bool
	}
	pieces := map[string][]piece{}
	var order []string

	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " \t\r\n;")
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		semi := strings.IndexByte(rest, ';')
		if semi >= 0 && semi < eq { // a parameter with no value
			rest = rest[semi+1:]
			continue
		}
		name := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimLeft(rest[eq+1:], " \t")
		var value string
		if strings.HasPrefix(rest, `"`) {
			value, rest = readQuoted(rest[1:])
		} else {
			end := strings.IndexByte(rest, ';')
			if end < 0 {
				end = len(rest)
			}
			value = strings.TrimSpace(stripComments(rest[:end]))
			rest = rest[end:]
		}
		if name == "" {
			continue
		}

		// RFC 2231: name*, name*N, name*N*.
		base, index, encoded := name, 0, false
		if star := strings.IndexByte(name, '*'); star >= 0 {
			base = name[:star]
			suffix := name[star+1:]
			if strings.HasSuffix(suffix, "*") {
				encoded = true
				suffix = strings.TrimSuffix(suffix, "*")
			}
			if suffix != "" {
				n, err := strconv.Atoi(suffix)
				if err != nil || n < 0 || n > 1000 {
					continue
				}
				index = n
			} else {
				encoded = true // "name*" carries an encoded value
			}
		}
		if _, seen := pieces[base]; !seen {
			order = append(order, base)
		}
		pieces[base] = append(pieces[base], piece{index, value, encoded})
	}

	for _, base := range order {
		list := pieces[base]
		// Keep the first piece of each index, then sort by index.
		byIndex := map[int]piece{}
		for _, pc := range list {
			if old, dup := byIndex[pc.index]; !dup || pc.encoded && !old.encoded {
				byIndex[pc.index] = pc
			}
		}
		var sb strings.Builder
		charset := ""
		for i := 0; i < len(byIndex); i++ {
			pc, ok := byIndex[i]
			if !ok {
				break
			}
			val := pc.value
			if pc.encoded {
				if i == 0 {
					// charset'language'text
					cs, afterCS, ok1 := strings.Cut(val, "'")
					_, text, ok2 := strings.Cut(afterCS, "'")
					if ok1 && ok2 {
						charset, val = cs, text
					}
				}
				if dec, err := url.PathUnescape(val); err == nil {
					val = dec
				}
			}
			sb.WriteString(val)
		}
		joined := sb.String()
		if charset != "" {
			joined, _ = DecodeCharset(charset, []byte(joined))
		} else if !utf8.ValidString(joined) {
			joined, _ = DecodeCharset("windows-1252", []byte(joined))
		}
		joined = DecodeWords(joined)
		if _, dup := params[base]; !dup {
			params[base] = joined
		}
	}
	return mediaType, params
}

func readQuoted(s string) (value, rest string) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			if i+1 < len(s) {
				i++
				sb.WriteByte(s[i])
			}
		case '"':
			return sb.String(), s[i+1:]
		case '\r', '\n':
			// Folding inside quotes is not content.
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String(), ""
}

// stripComments removes parenthesized comments from an unquoted token.
func stripComments(s string) string {
	if !strings.ContainsRune(s, '(') {
		return s
	}
	var sb strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if depth > 0 {
				i++
			} else {
				sb.WriteByte(s[i])
			}
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				sb.WriteByte(s[i])
			}
		}
	}
	return sb.String()
}

// appendParam appends `; name="value"` to a folder, using RFC 2231 when the
// value is not plain ASCII: `name="ascii fallback"; name*=UTF-8”%C3%A9`.
func (f *folder) appendParam(name, value string) {
	value = sanitizeUTF8(value)
	f.glue(";")
	if isToken(value) {
		f.word(name + "=" + value)
		return
	}
	if isPrintableASCII(value) {
		f.word(name + "=" + quoteString(value))
		return
	}
	f.word(name + "=" + quoteString(asciiFallback(value)))
	f.glue(";")
	f.word(name + "*=UTF-8''" + percentEncode(value))
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7F || strings.IndexByte(`()<>@,;:\"/[]?=`, c) >= 0 {
			return false
		}
	}
	return true
}

func isPrintableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7F {
			return false
		}
	}
	return true
}

// asciiFallback replaces every non-ASCII or control rune with "_" so clients
// that ignore RFC 2231 still show a usable name.
func asciiFallback(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if r < 0x20 || r >= 0x7F {
			sb.WriteByte('_')
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// percentEncode encodes s for an RFC 2231 value: attribute-char stays, the
// rest becomes %XX.
func percentEncode(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			strings.IndexByte("!#$&+-.^_`|~", c) >= 0 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('%')
			sb.WriteByte(hexUpper[c>>4])
			sb.WriteByte(hexUpper[c&15])
		}
	}
	return sb.String()
}
