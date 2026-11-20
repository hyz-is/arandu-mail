package dnsauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SPFResult is the result of an SPF evaluation (RFC 7208 section 2.6).
type SPFResult string

// The results.
const (
	SPFNone      SPFResult = "none"
	SPFNeutral   SPFResult = "neutral"
	SPFPass      SPFResult = "pass"
	SPFFail      SPFResult = "fail"
	SPFSoftFail  SPFResult = "softfail"
	SPFTempError SPFResult = "temperror"
	SPFPermError SPFResult = "permerror"
)

// SPFTerm is a mechanism of an SPF record.
type SPFTerm struct {
	// Qualifier is '+', '-', '~' or '?'.
	Qualifier byte
	// Mechanism is "all", "include", "a", "mx", "ptr", "ip4", "ip6" or "exists".
	Mechanism string
	// Domain is the domain-spec of include, a, mx, ptr and exists, as written
	// (macros not yet expanded). Empty means the current domain.
	Domain string
	// Network is the address range of ip4 and ip6.
	Network *net.IPNet
	// Prefix4 and Prefix6 are the CIDR lengths of a and mx; -1 means the whole
	// address (32 and 128).
	Prefix4, Prefix6 int
}

// SPFRecord is a parsed "v=spf1" record.
type SPFRecord struct {
	// Terms are the mechanisms in order.
	Terms []SPFTerm
	// Redirect and Exp are the modifiers of those names, as written.
	Redirect, Exp string
	// Raw is the record text.
	Raw string
}

// ErrSPFSyntax reports a record that is not valid SPF.
var ErrSPFSyntax = errors.New("dnsauth: invalid SPF record")

// isSPFRecord reports whether txt is an SPF version 1 record.
func isSPFRecord(txt string) bool {
	if len(txt) < 6 || !strings.EqualFold(txt[:6], "v=spf1") {
		return false
	}
	return len(txt) == 6 || txt[6] == ' '
}

// ParseSPF parses the text of a "v=spf1" record.
func ParseSPF(txt string) (*SPFRecord, error) {
	if !isSPFRecord(txt) {
		return nil, fmt.Errorf("%w: no v=spf1", ErrSPFSyntax)
	}
	rec := &SPFRecord{Raw: txt}
	for _, term := range strings.Fields(txt[6:]) {
		if strings.IndexByte(term, '=') > 0 && isModifierName(term[:strings.IndexByte(term, '=')]) {
			name, value, _ := strings.Cut(term, "=")
			switch strings.ToLower(name) {
			case "redirect":
				if rec.Redirect != "" || value == "" {
					return nil, fmt.Errorf("%w: redirect", ErrSPFSyntax)
				}
				rec.Redirect = value
			case "exp":
				if rec.Exp != "" || value == "" {
					return nil, fmt.Errorf("%w: exp", ErrSPFSyntax)
				}
				rec.Exp = value
			}
			continue
		}
		t, err := parseTerm(term)
		if err != nil {
			return nil, err
		}
		rec.Terms = append(rec.Terms, t)
	}
	return rec, nil
}

func isModifierName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !alpha {
			return false
		}
		if !alpha && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func parseTerm(s string) (SPFTerm, error) {
	t := SPFTerm{Qualifier: '+', Prefix4: -1, Prefix6: -1}
	switch s[0] {
	case '+', '-', '~', '?':
		t.Qualifier, s = s[0], s[1:]
	}
	name, rest := s, ""
	if i := strings.IndexAny(s, ":/"); i >= 0 {
		name, rest = s[:i], s[i:]
	}
	t.Mechanism = strings.ToLower(name)
	bad := func(why string) (SPFTerm, error) {
		return t, fmt.Errorf("%w: %s", ErrSPFSyntax, why)
	}
	switch t.Mechanism {
	case "all":
		if rest != "" {
			return bad("all takes no value")
		}
	case "include", "exists":
		if !strings.HasPrefix(rest, ":") || len(rest) == 1 {
			return bad(t.Mechanism + " needs a domain")
		}
		t.Domain = rest[1:]
	case "a", "mx", "ptr":
		if strings.HasPrefix(rest, ":") {
			dom, cidr, _ := strings.Cut(rest[1:], "/")
			if dom == "" {
				return bad("empty domain")
			}
			t.Domain = dom
			if cidr != "" {
				cidr = "/" + cidr
			}
			rest = cidr
		}
		if t.Mechanism == "ptr" {
			if rest != "" {
				return bad("ptr takes no prefix")
			}
			break
		}
		if rest != "" {
			if err := parseDualCIDR(rest, &t); err != nil {
				return bad(err.Error())
			}
		}
	case "ip4", "ip6":
		if !strings.HasPrefix(rest, ":") {
			return bad(t.Mechanism + " needs an address")
		}
		addr, cidr, hasCIDR := strings.Cut(rest[1:], "/")
		ip := net.ParseIP(addr)
		if ip == nil {
			return bad("invalid address " + addr)
		}
		bits, total := 32, 32
		if t.Mechanism == "ip4" {
			if ip.To4() == nil || strings.Contains(addr, ":") {
				return bad("ip4 needs an IPv4 address")
			}
			ip = ip.To4()
		} else {
			if ip.To4() != nil && !strings.Contains(addr, ":") {
				return bad("ip6 needs an IPv6 address")
			}
			bits, total = 128, 128
		}
		if hasCIDR {
			n, ok := atoiPlain(cidr)
			if !ok || n > total {
				return bad("invalid prefix length " + cidr)
			}
			bits = n
		}
		t.Network = &net.IPNet{IP: ip.Mask(net.CIDRMask(bits, total)), Mask: net.CIDRMask(bits, total)}
	default:
		return bad("unknown mechanism " + name)
	}
	return t, nil
}

// atoiPlain parses a decimal number with no sign and no leading zeros beyond a
// lone zero, as the CIDR length of SPF is written.
func atoiPlain(s string) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func parseDualCIDR(s string, t *SPFTerm) error {
	// "/24", "//64" or "/24//64"
	v4, v6, has6 := strings.Cut(strings.TrimPrefix(s, "/"), "//")
	if strings.HasPrefix(s, "//") {
		v4, v6, has6 = "", s[2:], true
	}
	if v4 != "" {
		n, ok := atoiPlain(v4)
		if !ok || n > 32 {
			return fmt.Errorf("invalid IPv4 prefix length %q", v4)
		}
		t.Prefix4 = n
	} else if !has6 {
		return errors.New("empty prefix length")
	}
	if has6 {
		n, ok := atoiPlain(v6)
		if !ok || n > 128 {
			return fmt.Errorf("invalid IPv6 prefix length %q", v6)
		}
		t.Prefix6 = n
	}
	return nil
}

// ---- evaluation ----

// SPFChecker evaluates SPF as a receiver does. The zero value uses the system
// resolver and the limits of the RFC.
type SPFChecker struct {
	// Resolver answers the lookups. Default DefaultResolver().
	Resolver Resolver
	// MaxDNSLookups bounds the terms that query DNS (include, a, mx, ptr,
	// exists and redirect). Default 10, the limit of RFC 7208 section 4.6.4.
	MaxDNSLookups int
	// MaxVoidLookups bounds the lookups that find nothing. Default 2.
	MaxVoidLookups int
	// Hostname is the name of the receiving host, for the %{r} macro of an
	// explanation. Default "unknown".
	Hostname string
	// Now is the time for the %{t} macro. Default time.Now.
	Now func() time.Time
}

// SPFVerdict is the outcome of Check.
type SPFVerdict struct {
	// Result is the SPF result.
	Result SPFResult
	// Domain is the domain whose record decided the result.
	Domain string
	// Mechanism is the term that matched, such as "ip4:192.0.2.0/24" or "all"
	// ("" when none matched or on an error).
	Mechanism string
	// Explanation is the text of the exp modifier, expanded, on a fail.
	Explanation string
	// Err says why the result is temperror or permerror.
	Err error
	// Lookups is how many DNS-querying terms were evaluated.
	Lookups int
}

var errSPFLimit = errors.New("dnsauth: SPF evaluation passed a DNS lookup limit")

type spfState struct {
	c       *SPFChecker
	ip      net.IP
	sender  string
	helo    string
	lookups int
	voids   int
}

// Check evaluates check_host(ip, domain, sender) of RFC 7208. domain is the
// domain to check, normally the one in sender; sender is the MAIL FROM address
// (empty for a bounce, in which case the postmaster of helo stands in for it).
func (c *SPFChecker) Check(ctx context.Context, ip net.IP, domain, sender, helo string) SPFVerdict {
	if c.Resolver == nil {
		c.Resolver = DefaultResolver()
	}
	if sender == "" {
		sender = "postmaster@" + helo
	} else if !strings.Contains(sender, "@") {
		sender = "postmaster@" + sender
	}
	st := &spfState{c: c, ip: ip, sender: sender, helo: helo}
	if v4 := ip.To4(); v4 != nil {
		st.ip = v4
	}
	v := st.check(ctx, normalize(domain), true)
	v.Lookups = st.lookups
	return v
}

func (s *spfState) maxLookups() int {
	if s.c.MaxDNSLookups > 0 {
		return s.c.MaxDNSLookups
	}
	return 10
}

func (s *spfState) maxVoids() int {
	if s.c.MaxVoidLookups > 0 {
		return s.c.MaxVoidLookups
	}
	return 2
}

// spend counts a DNS-querying term, and reports whether the limit is passed.
func (s *spfState) spend() error {
	s.lookups++
	if s.lookups > s.maxLookups() {
		return errSPFLimit
	}
	return nil
}

// void counts a lookup that found nothing.
func (s *spfState) void() error {
	s.voids++
	if s.voids > s.maxVoids() {
		return errSPFLimit
	}
	return nil
}

func validSPFDomain(d string) bool {
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(d, "."), ".") {
		if label == "" || len(label) > 63 {
			return false
		}
	}
	return true
}

func (s *spfState) check(ctx context.Context, domain string, top bool) SPFVerdict {
	v := SPFVerdict{Domain: domain}
	if !validSPFDomain(domain) {
		v.Result = SPFNone
		return v
	}
	txts, err := s.c.Resolver.LookupTXT(ctx, domain)
	if err != nil {
		if IsNotFound(err) {
			v.Result = SPFNone
			return v
		}
		v.Result, v.Err = SPFTempError, err
		return v
	}
	var records []string
	for _, t := range txts {
		if isSPFRecord(t) {
			records = append(records, t)
		}
	}
	switch len(records) {
	case 0:
		v.Result = SPFNone
		return v
	case 1:
	default:
		v.Result, v.Err = SPFPermError, errors.New("dnsauth: more than one SPF record")
		return v
	}
	rec, err := ParseSPF(records[0])
	if err != nil {
		v.Result, v.Err = SPFPermError, err
		return v
	}

	for _, t := range rec.Terms {
		match, err := s.matches(ctx, t, domain)
		if err != nil {
			if errors.Is(err, errSPFLimit) {
				v.Result, v.Err = SPFPermError, err
			} else if errors.Is(err, errPermError) {
				v.Result, v.Err = SPFPermError, err
			} else {
				v.Result, v.Err = SPFTempError, err
			}
			return v
		}
		if !match {
			continue
		}
		v.Mechanism = termString(t)
		switch t.Qualifier {
		case '+':
			v.Result = SPFPass
		case '-':
			v.Result = SPFFail
			if top && rec.Exp != "" {
				v.Explanation = s.explain(ctx, rec.Exp, domain)
			}
		case '~':
			v.Result = SPFSoftFail
		default:
			v.Result = SPFNeutral
		}
		return v
	}

	if rec.Redirect != "" {
		if err := s.spend(); err != nil {
			v.Result, v.Err = SPFPermError, err
			return v
		}
		target, err := s.expand(ctx, rec.Redirect, domain, false)
		if err != nil {
			v.Result, v.Err = SPFPermError, err
			return v
		}
		sub := s.check(ctx, normalize(target), top)
		if sub.Result == SPFNone {
			sub.Result, sub.Err = SPFPermError, errors.New("dnsauth: the redirect target has no SPF record")
		}
		return sub
	}
	v.Result = SPFNeutral
	return v
}

var errPermError = errors.New("dnsauth: SPF permanent error")

func termString(t SPFTerm) string {
	s := t.Mechanism
	switch {
	case t.Network != nil:
		s += ":" + t.Network.String()
	case t.Domain != "":
		s += ":" + t.Domain
	}
	return s
}

// matches evaluates one mechanism.
func (s *spfState) matches(ctx context.Context, t SPFTerm, current string) (bool, error) {
	switch t.Mechanism {
	case "all":
		return true, nil
	case "ip4":
		return s.ip.To4() != nil && t.Network.Contains(s.ip), nil
	case "ip6":
		return s.ip.To4() == nil && t.Network.Contains(s.ip), nil
	}
	if err := s.spend(); err != nil {
		return false, err
	}
	target := current
	if t.Domain != "" {
		var err error
		target, err = s.expand(ctx, t.Domain, current, false)
		if err != nil {
			return false, fmt.Errorf("%w: %v", errPermError, err)
		}
		target = normalize(target)
	}
	switch t.Mechanism {
	case "include":
		sub := s.check(ctx, target, false)
		switch sub.Result {
		case SPFPass:
			return true, nil
		case SPFFail, SPFSoftFail, SPFNeutral:
			return false, nil
		case SPFTempError:
			return false, sub.Err
		case SPFNone:
			return false, fmt.Errorf("%w: include of %s has no SPF record", errPermError, target)
		}
		return false, fmt.Errorf("%w: %v", errPermError, sub.Err)
	case "a":
		return s.matchesAddress(ctx, target, t)
	case "mx":
		mxs, err := s.c.Resolver.LookupMX(ctx, target)
		if err != nil {
			if IsNotFound(err) {
				return false, s.void()
			}
			return false, err
		}
		if len(mxs) > 10 {
			return false, fmt.Errorf("%w: more than 10 MX records for %s", errPermError, target)
		}
		for _, mx := range mxs {
			host := normalize(mx.Host)
			if host == "" {
				continue
			}
			ok, err := s.matchesAddress(ctx, host, t)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	case "exists":
		ips, err := s.c.Resolver.LookupIP(ctx, "ip4", target)
		if err != nil {
			if IsNotFound(err) {
				return false, s.void()
			}
			return false, err
		}
		return len(ips) > 0, nil
	case "ptr":
		return s.matchesPTR(ctx, target)
	}
	return false, nil
}

// matchesAddress looks the name up as an A or AAAA record, by the family of the
// client, and compares each address under the term's prefix length.
func (s *spfState) matchesAddress(ctx context.Context, host string, t SPFTerm) (bool, error) {
	network, bits, total := "ip4", t.Prefix4, 32
	if s.ip.To4() == nil {
		network, bits, total = "ip6", t.Prefix6, 128
	}
	if bits < 0 {
		bits = total
	}
	ips, err := s.c.Resolver.LookupIP(ctx, network, host)
	if err != nil {
		if IsNotFound(err) {
			return false, s.void()
		}
		return false, err
	}
	mask := net.CIDRMask(bits, total)
	client := s.ip
	if total == 32 {
		client = s.ip.To4()
	}
	for _, ip := range ips {
		if total == 32 {
			ip = ip.To4()
		}
		if ip == nil {
			continue
		}
		if ip.Mask(mask).Equal(client.Mask(mask)) {
			return true, nil
		}
	}
	return false, nil
}

// matchesPTR is the ptr mechanism: the names the client address resolves to,
// confirmed by a forward lookup, and equal to the target or below it.
func (s *spfState) matchesPTR(ctx context.Context, target string) (bool, error) {
	names, err := s.c.Resolver.LookupAddr(ctx, s.ip.String())
	if err != nil {
		if IsNotFound(err) {
			return false, s.void()
		}
		return false, nil // a ptr that cannot be resolved does not match
	}
	if len(names) > 10 {
		names = names[:10]
	}
	network := "ip4"
	if s.ip.To4() == nil {
		network = "ip6"
	}
	for _, n := range names {
		n = normalize(n)
		if n != target && !strings.HasSuffix(n, "."+target) {
			continue
		}
		ips, err := s.c.Resolver.LookupIP(ctx, network, n)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(s.ip) {
				return true, nil
			}
		}
	}
	return false, nil
}

// explain fetches and expands the explanation of a fail. Any problem leaves it
// empty: an explanation is a courtesy, never a reason to change the result.
func (s *spfState) explain(ctx context.Context, spec, domain string) string {
	name, err := s.expand(ctx, spec, domain, false)
	if err != nil {
		return ""
	}
	txts, err := s.c.Resolver.LookupTXT(ctx, normalize(name))
	if err != nil || len(txts) != 1 {
		return ""
	}
	out, err := s.expand(ctx, txts[0], domain, true)
	if err != nil {
		return ""
	}
	return out
}

// ---- macros (RFC 7208 section 7) ----

// ErrSPFMacro reports a malformed macro in a domain-spec.
var ErrSPFMacro = errors.New("dnsauth: invalid SPF macro")

// expand expands the macros of a domain-spec or, with exp true, of an
// explanation string.
func (s *spfState) expand(ctx context.Context, spec, domain string, exp bool) (string, error) {
	if !strings.Contains(spec, "%") {
		return spec, nil
	}
	var sb strings.Builder
	for i := 0; i < len(spec); i++ {
		c := spec[i]
		if c != '%' {
			sb.WriteByte(c)
			continue
		}
		i++
		if i >= len(spec) {
			return "", ErrSPFMacro
		}
		switch spec[i] {
		case '%':
			sb.WriteByte('%')
		case '_':
			sb.WriteByte(' ')
		case '-':
			sb.WriteString("%20")
		case '{':
			end := strings.IndexByte(spec[i:], '}')
			if end < 0 {
				return "", ErrSPFMacro
			}
			body := spec[i+1 : i+end]
			i += end
			val, err := s.macro(ctx, body, domain, exp)
			if err != nil {
				return "", err
			}
			sb.WriteString(val)
		default:
			return "", ErrSPFMacro
		}
	}
	return sb.String(), nil
}

func (s *spfState) macro(ctx context.Context, body, domain string, exp bool) (string, error) {
	if body == "" {
		return "", ErrSPFMacro
	}
	letter := body[0]
	rest := body[1:]
	// transformers: *DIGIT ["r"] *delimiter
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	keep := -1
	if j > 0 {
		n, err := strconv.Atoi(rest[:j])
		if err != nil || n == 0 {
			return "", ErrSPFMacro
		}
		keep = n
	}
	reverse := false
	if j < len(rest) && (rest[j] == 'r' || rest[j] == 'R') {
		reverse = true
		j++
	}
	delims := rest[j:]
	if delims == "" {
		delims = "."
	}
	for i := 0; i < len(delims); i++ {
		if !strings.ContainsRune(".-+,/_=", rune(delims[i])) {
			return "", ErrSPFMacro
		}
	}

	local, senderDomain, _ := strings.Cut(s.sender, "@")
	if at := strings.LastIndexByte(s.sender, '@'); at >= 0 {
		local, senderDomain = s.sender[:at], s.sender[at+1:]
	}
	var val string
	switch lower(letter) {
	case 's':
		val = s.sender
	case 'l':
		val = local
	case 'o':
		val = senderDomain
	case 'd':
		val = domain
	case 'i':
		val = ipMacro(s.ip)
	case 'p':
		val = s.validatedName(ctx, domain)
	case 'v':
		val = "in-addr"
		if s.ip.To4() == nil {
			val = "ip6"
		}
	case 'h':
		val = s.helo
	case 'c':
		if !exp {
			return "", ErrSPFMacro
		}
		val = s.ip.String()
	case 'r':
		if !exp {
			return "", ErrSPFMacro
		}
		val = s.c.Hostname
		if val == "" {
			val = "unknown"
		}
	case 't':
		if !exp {
			return "", ErrSPFMacro
		}
		now := time.Now
		if s.c.Now != nil {
			now = s.c.Now
		}
		val = strconv.FormatInt(now().Unix(), 10)
	default:
		return "", ErrSPFMacro
	}

	parts := splitAny(val, delims)
	if reverse {
		for a, b := 0, len(parts)-1; a < b; a, b = a+1, b-1 {
			parts[a], parts[b] = parts[b], parts[a]
		}
	}
	if keep >= 0 && keep < len(parts) {
		parts = parts[len(parts)-keep:]
	}
	out := strings.Join(parts, ".")
	if letter >= 'A' && letter <= 'Z' {
		out = url.QueryEscape(out)
		out = strings.ReplaceAll(out, "+", "%20")
	}
	return out, nil
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// splitAny cuts s at every character of delims and keeps the empty parts.
func splitAny(s, delims string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(delims, s[i]) >= 0 {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// ipMacro writes the address as the %{i} macro does: dotted for IPv4, and the
// 32 dot-separated nibbles for IPv6.
func ipMacro(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	ip16 := ip.To16()
	var sb strings.Builder
	for i, b := range ip16 {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteByte("0123456789abcdef"[b>>4])
		sb.WriteByte('.')
		sb.WriteByte("0123456789abcdef"[b&15])
	}
	return sb.String()
}

// validatedName is the %{p} macro: a name of the client that resolves back to
// it, preferring one under the domain, or "unknown".
func (s *spfState) validatedName(ctx context.Context, domain string) string {
	names, err := s.c.Resolver.LookupAddr(ctx, s.ip.String())
	if err != nil {
		return "unknown"
	}
	network := "ip4"
	if s.ip.To4() == nil {
		network = "ip6"
	}
	best := ""
	for i, n := range names {
		if i >= 10 {
			break
		}
		n = normalize(n)
		ips, err := s.c.Resolver.LookupIP(ctx, network, n)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(s.ip) {
				if n == domain || strings.HasSuffix(n, "."+domain) {
					return n
				}
				if best == "" {
					best = n
				}
			}
		}
	}
	if best == "" {
		return "unknown"
	}
	return best
}
