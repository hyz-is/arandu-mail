// Package puny converts internationalized domain names between their Unicode
// and ASCII-compatible forms with Punycode (RFC 3492).
//
// It does the mapping a mail library needs and no more: labels are lowercased,
// non-ASCII labels are encoded with the "xn--" prefix, and the length limits of
// the DNS are enforced. It does not apply the full IDNA 2008 tables, so a
// domain that needs normalization beyond case folding is the caller's to
// prepare.
package puny

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	base        = 36
	tMin        = 1
	tMax        = 26
	skew        = 38
	damp        = 700
	initialBias = 72
	initialN    = 128
	prefix      = "xn--"
)

// ErrInvalid reports a label or domain that cannot be encoded or decoded.
var ErrInvalid = errors.New("puny: invalid domain name")

// IsASCII reports whether s holds only 7-bit characters.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// ToASCII returns the ASCII form of a domain name: every label lowercased and,
// when it holds a non-ASCII character, Punycode-encoded behind "xn--". A
// trailing dot is kept. A name that is already ASCII is returned lowercased
// without allocating when it holds no capital letter.
func ToASCII(domain string) (string, error) {
	if domain == "" {
		return "", ErrInvalid
	}
	if IsASCII(domain) && !hasUpper(domain) {
		return checkLengths(domain)
	}
	if IsASCII(domain) {
		return checkLengths(strings.ToLower(domain))
	}
	var b strings.Builder
	b.Grow(len(domain) * 2)
	rest := domain
	for first := true; ; first = false {
		label, tail, more := strings.Cut(rest, ".")
		if !first {
			b.WriteByte('.')
		}
		if label == "" && more && !first {
			return "", ErrInvalid
		}
		if IsASCII(label) {
			b.WriteString(strings.ToLower(label))
		} else {
			enc, err := encodeLabel(strings.ToLower(label))
			if err != nil {
				return "", err
			}
			b.WriteString(prefix)
			b.WriteString(enc)
		}
		if !more {
			break
		}
		rest = tail
	}
	return checkLengths(b.String())
}

// ToUnicode returns the Unicode form of a domain name. A label that is not
// valid Punycode is left as it was.
func ToUnicode(domain string) string {
	if !strings.Contains(domain, prefix) && !strings.Contains(strings.ToLower(domain), prefix) {
		return domain
	}
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if len(label) > len(prefix) && strings.EqualFold(label[:len(prefix)], prefix) {
			if dec, err := decodeLabel(strings.ToLower(label[len(prefix):])); err == nil {
				labels[i] = dec
			}
		}
	}
	return strings.Join(labels, ".")
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

func checkLengths(s string) (string, error) {
	trimmed := strings.TrimSuffix(s, ".")
	if trimmed == "" || len(trimmed) > 253 {
		return "", ErrInvalid
	}
	for rest := trimmed; ; {
		label, tail, more := strings.Cut(rest, ".")
		if label == "" || len(label) > 63 {
			return "", ErrInvalid
		}
		if !more {
			break
		}
		rest = tail
	}
	return s, nil
}

func adapt(delta, numPoints int, first bool) int {
	if first {
		delta /= damp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((base-tMin)*tMax)/2 {
		delta /= base - tMin
		k += base
	}
	return k + (base-tMin+1)*delta/(delta+skew)
}

func digit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func encodeLabel(label string) (string, error) {
	runes := []rune(label)
	out := make([]byte, 0, len(label)+8)
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := initialN, 0, initialBias
	for handled < len(runes) {
		m := int(^uint32(0) >> 1)
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (int(^uint32(0)>>1)-delta)/(handled+1) {
			return "", ErrInvalid
		}
		delta += (m - n) * (handled + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
				continue
			}
			if int(r) != n {
				continue
			}
			q := delta
			for k := base; ; k += base {
				t := k - bias
				switch {
				case t < tMin:
					t = tMin
				case t > tMax:
					t = tMax
				}
				if q < t {
					break
				}
				out = append(out, digit(t+(q-t)%(base-t)))
				q = (q - t) / (base - t)
			}
			out = append(out, digit(q))
			bias = adapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return string(out), nil
}

func decodeLabel(s string) (string, error) {
	var out []rune
	rest := s
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		for _, c := range s[:i] {
			if c >= utf8.RuneSelf {
				return "", ErrInvalid
			}
			out = append(out, c)
		}
		rest = s[i+1:]
	}
	n, i, bias := initialN, 0, initialBias
	for pos := 0; pos < len(rest); {
		oldi, w := i, 1
		for k := base; ; k += base {
			if pos >= len(rest) {
				return "", ErrInvalid
			}
			c := rest[pos]
			pos++
			var d int
			switch {
			case c >= 'a' && c <= 'z':
				d = int(c - 'a')
			case c >= '0' && c <= '9':
				d = int(c-'0') + 26
			default:
				return "", ErrInvalid
			}
			if d > (int(^uint32(0)>>1)-i)/w {
				return "", ErrInvalid
			}
			i += d * w
			t := k - bias
			switch {
			case t < tMin:
				t = tMin
			case t > tMax:
				t = tMax
			}
			if d < t {
				break
			}
			if w > int(^uint32(0)>>1)/(base-t) {
				return "", ErrInvalid
			}
			w *= base - t
		}
		bias = adapt(i-oldi, len(out)+1, oldi == 0)
		if i/(len(out)+1) > int(^uint32(0)>>1)-n {
			return "", ErrInvalid
		}
		n += i / (len(out) + 1)
		i %= len(out) + 1
		if n > unicode.MaxRune || !utf8.ValidRune(rune(n)) {
			return "", ErrInvalid
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = rune(n)
		i++
	}
	return string(out), nil
}
