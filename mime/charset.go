package mime

import (
	"strings"
	"unicode/utf8"
)

// windows1252 maps the bytes 0x80 to 0x9F of Windows-1252 to code points.
// The five bytes Windows leaves undefined map to the C1 control of the same
// value, which is what browsers do.
var windows1252 = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// iso885915 lists the eight code points where ISO-8859-15 differs from
// ISO-8859-1.
var iso885915 = map[byte]rune{
	0xA4: 0x20AC, 0xA6: 0x0160, 0xA8: 0x0161, 0xB4: 0x017D,
	0xB8: 0x017E, 0xBC: 0x0152, 0xBD: 0x0153, 0xBE: 0x0178,
}

type charsetKind uint8

const (
	charsetUnknown charsetKind = iota
	charsetUTF8
	charsetLatin1 // read as Windows-1252, the superset every mail client treats it as
	charsetLatin9
)

// charsetKindOf maps a charset label to the decoder that reads it.
func charsetKindOf(label string) charsetKind {
	label = strings.ToLower(strings.TrimSpace(label))
	switch label {
	case "", "utf-8", "utf8", "unicode-1-1-utf-8":
		return charsetUTF8
	case "us-ascii", "ascii", "ansi_x3.4-1968", "iso-8859-1", "iso8859-1", "iso_8859-1",
		"latin1", "l1", "windows-1252", "cp1252", "x-cp1252", "iso-ir-100", "ibm819", "cp819":
		return charsetLatin1
	case "iso-8859-15", "iso8859-15", "iso_8859-15", "latin9", "latin-9", "l9":
		return charsetLatin9
	}
	return charsetUnknown
}

// KnownCharset reports whether DecodeCharset reads the charset without a
// fallback.
func KnownCharset(label string) bool { return charsetKindOf(label) != charsetUnknown }

// DecodeCharset converts b, written in the named charset, to a UTF-8 string.
//
// UTF-8 (and an empty label) is validated, and invalid sequences become
// U+FFFD. US-ASCII, ISO-8859-1 and Windows-1252 are read as Windows-1252, and
// ISO-8859-15 as itself. For any other label the bytes are returned as UTF-8
// with invalid sequences replaced and ok is false, so a caller can record that
// the text was not converted.
func DecodeCharset(label string, b []byte) (s string, ok bool) {
	switch charsetKindOf(label) {
	case charsetUTF8:
		return validUTF8(b), true
	case charsetLatin1:
		return decodeSingleByte(b, nil), true
	case charsetLatin9:
		return decodeSingleByte(b, iso885915), true
	}
	return validUTF8(b), false
}

func validUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

func decodeSingleByte(b []byte, delta map[byte]rune) string {
	ascii := true
	for _, c := range b {
		if c >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b) + len(b)/2)
	for _, c := range b {
		switch {
		case c < utf8.RuneSelf:
			sb.WriteByte(c)
		case delta != nil && delta[c] != 0:
			sb.WriteRune(delta[c])
		case delta == nil && c < 0xA0:
			sb.WriteRune(windows1252[c-0x80])
		default:
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}
