package mime

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/hyz-is/arandu-mail/internal/puny"
)

// Address is a mailbox: an optional display name and an address.
//
// Address holds the addr-spec as it travels in SMTP ("local@domain"): a local
// part that needs quoting is kept quoted, and the domain is kept as it was
// written, Unicode or ASCII.
type Address struct {
	// Name is the display name, decoded and unquoted.
	Name string
	// Address is the addr-spec, "local@domain".
	Address string
}

// Errors returned by the address functions.
var (
	// ErrInvalidAddress reports text that is not an address.
	ErrInvalidAddress = errors.New("mime: invalid address")
	// ErrNeedsSMTPUTF8 reports an address whose local part is not ASCII, which
	// only travels on a path that offers SMTPUTF8 (RFC 6531).
	ErrNeedsSMTPUTF8 = errors.New("mime: the local part is not ASCII and SMTPUTF8 is off")
)

// Local returns the part of the address before the last "@".
func (a Address) Local() string {
	i := strings.LastIndexByte(a.Address, '@')
	if i < 0 {
		return a.Address
	}
	return a.Address[:i]
}

// Domain returns the part of the address after the last "@", as written.
func (a Address) Domain() string {
	i := strings.LastIndexByte(a.Address, '@')
	if i < 0 {
		return ""
	}
	return a.Address[i+1:]
}

// ASCIIDomain returns the domain with every non-ASCII label in Punycode and
// lowercased, or the domain unchanged when it cannot be converted.
func (a Address) ASCIIDomain() string {
	d := a.Domain()
	if strings.HasPrefix(d, "[") {
		return d
	}
	if ascii, err := puny.ToASCII(d); err == nil {
		return ascii
	}
	return d
}

// Envelope returns the address as it goes into SMTP MAIL FROM and RCPT TO: the
// domain in its ASCII form. It fails with ErrNeedsSMTPUTF8 when the local part
// holds non-ASCII characters and smtputf8 is false.
func (a Address) Envelope(smtputf8 bool) (string, error) {
	local := a.Local()
	if !smtputf8 && !puny.IsASCII(local) {
		return "", ErrNeedsSMTPUTF8
	}
	if smtputf8 {
		return local + "@" + a.Domain(), nil
	}
	return local + "@" + a.ASCIIDomain(), nil
}

// String formats the address the way ParseAddress reads it, with the display
// name quoted when it needs to be and encoded as RFC 2047 words when it is not
// ASCII.
func (a Address) String() string {
	f := folder{dst: make([]byte, 0, 64), sep: false}
	f.appendAddress(a, false)
	return string(f.dst)
}

// ParseAddress parses one mailbox, such as "Ana <ana@example.com>" or
// "ana@example.com". Encoded words in the display name are decoded.
func ParseAddress(s string) (Address, error) {
	list, err := ParseAddressList(s)
	if err != nil {
		return Address{}, err
	}
	if len(list) != 1 {
		return Address{}, fmt.Errorf("%w: expected one address, found %d", ErrInvalidAddress, len(list))
	}
	return list[0], nil
}

// ParseAddressList parses a comma separated list of mailboxes and groups as
// they appear in a To, Cc or Reply-To header. The members of a group are
// returned as ordinary addresses and the group name is dropped. An empty or
// blank string yields an empty list.
func ParseAddressList(s string) ([]Address, error) {
	p := addrParser{s: s}
	list, err := p.parseList(false)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// parseAddressListLenient parses a header from received mail: an item that is
// not an address is skipped and described in the returned problems.
func parseAddressListLenient(s string) (list []Address, problems []string) {
	p := addrParser{s: s}
	list, _ = p.parseList(true)
	return list, p.problems
}

type addrParser struct {
	s        string
	i        int
	problems []string
}

func (p *addrParser) eof() bool { return p.i >= len(p.s) }

func (p *addrParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

// skipCFWS skips white space and comments, and returns the text of the
// comments.
func (p *addrParser) skipCFWS() (comments string) {
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			p.i++
		case c == '(':
			start := p.i + 1
			depth := 0
			for p.i < len(p.s) {
				ch := p.s[p.i]
				p.i++
				if ch == '\\' && p.i < len(p.s) {
					p.i++
					continue
				}
				if ch == '(' {
					depth++
				} else if ch == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			end := p.i
			if depth == 0 {
				end-- // the closing parenthesis is not content
			}
			if end > start && end <= len(p.s) {
				comments += unquoteComment(p.s[start:end])
			}
		default:
			return comments
		}
	}
	return comments
}

func unquoteComment(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func (p *addrParser) parseList(lenient bool) ([]Address, error) {
	var out []Address
	for {
		p.skipCFWS()
		if p.eof() {
			return out, nil
		}
		if p.peek() == ',' || p.peek() == ';' {
			p.i++
			continue
		}
		start := p.i
		got, err := p.parseItem()
		if err != nil {
			if !lenient {
				return nil, err
			}
			p.problems = append(p.problems, err.Error())
			// Skip to the next comma outside quotes.
			p.i = start
			p.skipItem()
			continue
		}
		out = append(out, got...)
		p.skipCFWS()
		if p.eof() {
			return out, nil
		}
		switch p.peek() {
		case ',', ';':
			p.i++
		default:
			err := fmt.Errorf("%w: unexpected %q in %q", ErrInvalidAddress, p.peek(), p.s)
			if !lenient {
				return nil, err
			}
			p.problems = append(p.problems, err.Error())
			p.skipItem()
		}
	}
}

// skipItem advances to just after the next comma that is not inside quotes or
// an angle address.
func (p *addrParser) skipItem() {
	inQuote, inAngle := false, false
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\' && inQuote:
			p.i++
		case c == '"':
			inQuote = !inQuote
		case c == '<' && !inQuote:
			inAngle = true
		case c == '>' && !inQuote:
			inAngle = false
		case c == ',' && !inQuote && !inAngle:
			return
		}
	}
}

// parseItem parses a mailbox or a group.
func (p *addrParser) parseItem() ([]Address, error) {
	start := p.i
	// A bare addr-spec, optionally followed by a comment used as the name.
	if spec, ok := p.tryAddrSpec(); ok {
		comment := p.skipCFWS()
		if p.eof() || p.peek() == ',' || p.peek() == ';' {
			name := strings.TrimSpace(DecodeWords(comment))
			return []Address{{Name: name, Address: spec}}, nil
		}
	}
	p.i = start
	phrase, err := p.parsePhrase()
	if err != nil {
		return nil, err
	}
	p.skipCFWS()
	switch p.peek() {
	case ':': // group
		p.i++
		var members []Address
		for {
			p.skipCFWS()
			if p.eof() {
				return members, nil
			}
			if p.peek() == ';' {
				return members, nil
			}
			if p.peek() == ',' {
				p.i++
				continue
			}
			got, err := p.parseItem()
			if err != nil {
				return nil, err
			}
			members = append(members, got...)
		}
	case '<':
		p.i++
		spec, err := p.parseAngle()
		if err != nil {
			return nil, err
		}
		return []Address{{Name: phrase, Address: spec}}, nil
	}
	return nil, fmt.Errorf("%w: no address in %q", ErrInvalidAddress, p.s[start:min(len(p.s), start+40)])
}

// parseAngle reads the addr-spec after "<" up to and including ">", dropping an
// obsolete source route.
func (p *addrParser) parseAngle() (string, error) {
	p.skipCFWS()
	if p.peek() == '@' { // obs-route: "@a,@b:"
		for !p.eof() && p.peek() != ':' && p.peek() != '>' {
			p.i++
		}
		if p.peek() == ':' {
			p.i++
		}
	}
	p.skipCFWS()
	if p.peek() == '>' { // "<>" is the null reverse path
		p.i++
		return "", fmt.Errorf("%w: empty address", ErrInvalidAddress)
	}
	spec, ok := p.tryAddrSpec()
	if !ok {
		return "", fmt.Errorf("%w: bad addr-spec in %q", ErrInvalidAddress, p.s)
	}
	p.skipCFWS()
	if p.peek() != '>' {
		return "", fmt.Errorf("%w: missing > in %q", ErrInvalidAddress, p.s)
	}
	p.i++
	return spec, nil
}

// parsePhrase reads the words before "<" or ":" and decodes encoded words.
func (p *addrParser) parsePhrase() (string, error) {
	var words []string
	for {
		p.skipCFWS()
		if p.eof() {
			break
		}
		c := p.peek()
		if c == '<' || c == ':' || c == ',' || c == ';' {
			break
		}
		if c == '"' {
			q, err := p.parseQuoted()
			if err != nil {
				return "", err
			}
			words = append(words, q)
			continue
		}
		start := p.i
		for !p.eof() && isPhraseChar(p.peek()) {
			p.i++
		}
		if p.i == start {
			return "", fmt.Errorf("%w: unexpected %q in %q", ErrInvalidAddress, p.peek(), p.s)
		}
		words = append(words, p.s[start:p.i])
	}
	return strings.TrimSpace(DecodeWords(strings.Join(words, " "))), nil
}

func isPhraseChar(c byte) bool {
	return isAtext(c) || c == '.' || c >= utf8.RuneSelf
}

// isAtext reports whether c may appear in an atom (RFC 5322 section 3.2.3).
func isAtext(c byte) bool {
	switch {
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// parseQuoted reads a quoted-string starting at the opening quote and returns
// its unescaped content.
func (p *addrParser) parseQuoted() (string, error) {
	p.i++ // opening quote
	var sb strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		p.i++
		switch c {
		case '\\':
			if p.i < len(p.s) {
				if e := p.s[p.i]; e != '\r' && e != '\n' && e != 0 {
					sb.WriteByte(e)
				}
				p.i++
			}
		case '"':
			return sb.String(), nil
		case '\r', '\n', 0:
			// Folding white space inside a quoted string is not content.
		default:
			sb.WriteByte(c)
		}
	}
	return "", fmt.Errorf("%w: unterminated quoted string", ErrInvalidAddress)
}

// tryAddrSpec reads local-part "@" domain at the current position. On failure
// the position is left where it was.
func (p *addrParser) tryAddrSpec() (string, bool) {
	start := p.i
	p.skipCFWS()
	var local string
	if p.peek() == '"' {
		q, err := p.parseQuoted()
		if err != nil {
			p.i = start
			return "", false
		}
		local = quoteLocalIfNeeded(q)
	} else {
		ls := p.i
		for !p.eof() && (isAtext(p.peek()) || p.peek() == '.' || p.peek() >= utf8.RuneSelf) {
			p.i++
		}
		local = p.s[ls:p.i]
		if local == "" || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			p.i = start
			return "", false
		}
		if !utf8.ValidString(local) {
			p.i = start
			return "", false
		}
	}
	p.skipCFWS()
	if p.peek() != '@' {
		p.i = start
		return "", false
	}
	p.i++
	p.skipCFWS()
	var domain string
	if p.peek() == '[' {
		ds := p.i
		p.i++ // the opening bracket
		for !p.eof() && p.peek() != ']' {
			if c := p.peek(); c <= ' ' || c >= 0x7F || c == '[' || c == '\\' {
				p.i = start
				return "", false
			}
			p.i++
		}
		if p.eof() {
			p.i = start
			return "", false
		}
		p.i++
		domain = p.s[ds:p.i]
	} else {
		ds := p.i
		for !p.eof() && (isDomainChar(p.peek()) || p.peek() >= utf8.RuneSelf) {
			p.i++
		}
		domain = p.s[ds:p.i]
		if !validDomain(domain) {
			p.i = start
			return "", false
		}
	}
	if len(local) > 64+192 || len(domain) > 255 {
		p.i = start
		return "", false
	}
	return local + "@" + domain, true
}

func isDomainChar(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '.' || c == '_'
}

func validDomain(d string) bool {
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 || !utf8.ValidString(d) {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63*4 { // a Unicode label is longer than its Punycode form
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// quoteLocalIfNeeded returns a local part as an addr-spec writes it: bare when
// it is a dot-atom, quoted otherwise.
func quoteLocalIfNeeded(s string) string {
	if s != "" && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".") && !strings.Contains(s, "..") {
		bare := true
		for i := 0; i < len(s); i++ {
			if !(isAtext(s[i]) || s[i] == '.' || s[i] >= utf8.RuneSelf) {
				bare = false
				break
			}
		}
		if bare {
			return s
		}
	}
	var sb strings.Builder
	sb.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	sb.WriteByte('"')
	return sb.String()
}
