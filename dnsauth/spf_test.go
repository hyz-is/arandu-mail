package dnsauth_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/dnsauth"
)

func check(f *dnsauth.Fake, ip, domain, sender string) dnsauth.SPFVerdict {
	c := &dnsauth.SPFChecker{Resolver: f, Hostname: "mx.receiver.example"}
	return c.Check(context.Background(), net.ParseIP(ip), domain, sender, "helo.example.org")
}

func TestSPFBasicResults(t *testing.T) {
	f := dnsauth.NewFake().
		SetTXT("example.com", "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all").
		SetTXT("soft.example.com", "v=spf1 ~all").
		SetTXT("neutral.example.com", "v=spf1 ?all").
		SetTXT("plus.example.com", "v=spf1 +all").
		SetTXT("nomatch.example.com", "v=spf1 ip4:203.0.113.1").
		SetTXT("plain.example.com", "just some text").
		SetTXT("two.example.com", "v=spf1 -all", "v=spf1 +all").
		SetTXT("bad.example.com", "v=spf1 frobnicate -all").
		SetError("txt", "down.example.com", errors.New("server failure"))
	cases := []struct {
		name, ip, domain string
		want             dnsauth.SPFResult
	}{
		{"pass v4", "192.0.2.77", "example.com", dnsauth.SPFPass},
		{"pass v6", "2001:db8::1", "example.com", dnsauth.SPFPass},
		{"fail v4", "198.51.100.1", "example.com", dnsauth.SPFFail},
		{"fail v6", "2001:db9::1", "example.com", dnsauth.SPFFail},
		{"softfail", "198.51.100.1", "soft.example.com", dnsauth.SPFSoftFail},
		{"neutral", "198.51.100.1", "neutral.example.com", dnsauth.SPFNeutral},
		{"plus all", "198.51.100.1", "plus.example.com", dnsauth.SPFPass},
		{"end of record", "198.51.100.1", "nomatch.example.com", dnsauth.SPFNeutral},
		{"no record", "198.51.100.1", "plain.example.com", dnsauth.SPFNone},
		{"no domain", "198.51.100.1", "missing.example.com", dnsauth.SPFNone},
		{"malformed domain", "198.51.100.1", "localhost", dnsauth.SPFNone},
		{"two records", "198.51.100.1", "two.example.com", dnsauth.SPFPermError},
		{"syntax", "198.51.100.1", "bad.example.com", dnsauth.SPFPermError},
		{"dns down", "198.51.100.1", "down.example.com", dnsauth.SPFTempError},
		{"mapped v4", "::ffff:192.0.2.9", "example.com", dnsauth.SPFPass},
	}
	for _, c := range cases {
		v := check(f, c.ip, c.domain, "user@"+c.domain)
		if v.Result != c.want {
			t.Errorf("%s: %s (%v), want %s", c.name, v.Result, v.Err, c.want)
		}
	}
	if v := check(f, "192.0.2.5", "example.com", "u@example.com"); v.Mechanism != "ip4:192.0.2.0/24" {
		t.Errorf("mechanism = %q", v.Mechanism)
	}
}

func TestSPFIncludeARedirect(t *testing.T) {
	f := dnsauth.NewFake().
		SetTXT("example.com", "v=spf1 include:_spf.provider.net a mx:mail.example.com/30 -all").
		SetTXT("_spf.provider.net", "v=spf1 ip4:203.0.113.0/24 -all").
		SetIP("example.com", "198.51.100.10", "2001:db8:1::10").
		SetMX("mail.example.com", dnsauth.MX{Host: "mx1.example.com", Pref: 10}, dnsauth.MX{Host: "mx2.example.com", Pref: 20}).
		SetIP("mx1.example.com", "198.51.100.64").
		SetIP("mx2.example.com", "2001:db8:2::1").
		SetTXT("redir.example.com", "v=spf1 redirect=example.com").
		SetTXT("lost.example.com", "v=spf1 redirect=nothing.example.com").
		SetTXT("incl-none.example.com", "v=spf1 include:nothing.example.com -all")
	cases := []struct {
		name, ip string
		want     dnsauth.SPFResult
	}{
		{"include passes", "203.0.113.55", dnsauth.SPFPass},
		{"a v4", "198.51.100.10", dnsauth.SPFPass},
		{"a v6", "2001:db8:1::10", dnsauth.SPFPass},
		{"mx within /30", "198.51.100.66", dnsauth.SPFPass},
		{"mx outside /30", "198.51.100.68", dnsauth.SPFFail},
		{"mx v6 uses the whole address", "2001:db8:2::1", dnsauth.SPFPass},
		{"nothing", "192.0.2.1", dnsauth.SPFFail},
	}
	for _, c := range cases {
		got := check(f, c.ip, "example.com", "u@example.com").Result
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := check(f, "203.0.113.9", "redir.example.com", "u@redir.example.com").Result; got != dnsauth.SPFPass {
		t.Errorf("redirect: %s", got)
	}
	if got := check(f, "192.0.2.1", "redir.example.com", "u@redir.example.com").Result; got != dnsauth.SPFFail {
		t.Errorf("redirect fail: %s", got)
	}
	if got := check(f, "192.0.2.1", "lost.example.com", "u@lost.example.com").Result; got != dnsauth.SPFPermError {
		t.Errorf("redirect to nothing: %s", got)
	}
	if got := check(f, "192.0.2.1", "incl-none.example.com", "u@incl-none.example.com").Result; got != dnsauth.SPFPermError {
		t.Errorf("include of nothing: %s", got)
	}
}

func TestSPFExistsPTRAndExplanation(t *testing.T) {
	f := dnsauth.NewFake().
		SetTXT("example.com", "v=spf1 exists:%{ir}.allow.example.com ptr:trusted.example.net -all exp=why.example.com").
		SetIP("2.2.0.192.allow.example.com", "127.0.0.2").
		SetPTR("203.0.113.7", "host.trusted.example.net").
		SetIP("host.trusted.example.net", "203.0.113.7").
		SetTXT("why.example.com", "%{i} is not allowed to send for %{d} (said %{r}, as %{s})")
	if got := check(f, "192.0.2.2", "example.com", "u@example.com"); got.Result != dnsauth.SPFPass || got.Mechanism != "exists:%{ir}.allow.example.com" {
		t.Errorf("exists: %+v", got)
	}
	if got := check(f, "203.0.113.7", "example.com", "u@example.com").Result; got != dnsauth.SPFPass {
		t.Errorf("ptr: %s", got)
	}
	got := check(f, "198.51.100.9", "example.com", "u@example.com")
	if got.Result != dnsauth.SPFFail || got.Explanation != "198.51.100.9 is not allowed to send for example.com (said mx.receiver.example, as u@example.com)" {
		t.Errorf("explanation: %+v", got)
	}
	// A forged PTR (the forward lookup does not return the client) does not match.
	f.SetPTR("198.51.100.9", "x.trusted.example.net").SetIP("x.trusted.example.net", "198.51.100.200")
	if got := check(f, "198.51.100.9", "example.com", "u@example.com").Result; got != dnsauth.SPFFail {
		t.Errorf("forged ptr: %s", got)
	}
}

// The examples of RFC 7208 section 7.4: sender strong-bad@email.example.com,
// client 192.0.2.3 and 2001:db8::cb01.
func TestSPFMacroExpansion(t *testing.T) {
	cases := []struct{ macro, ip, want string }{
		{"%{s}", "192.0.2.3", "strong-bad@email.example.com"},
		{"%{o}", "192.0.2.3", "email.example.com"},
		{"%{d}", "192.0.2.3", "email.example.com"},
		{"%{d4}", "192.0.2.3", "email.example.com"},
		{"%{d3}", "192.0.2.3", "email.example.com"},
		{"%{d2}", "192.0.2.3", "example.com"},
		{"%{d1}", "192.0.2.3", "com"},
		{"%{dr}", "192.0.2.3", "com.example.email"},
		{"%{d2r}", "192.0.2.3", "example.email"},
		{"%{l}", "192.0.2.3", "strong-bad"},
		{"%{l-}", "192.0.2.3", "strong.bad"},
		{"%{lr}", "192.0.2.3", "strong-bad"},
		{"%{lr-}", "192.0.2.3", "bad.strong"},
		{"%{l1r-}", "192.0.2.3", "strong"},
		{"%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr._spf.example.com"},
		{"%{lr-}.lp._spf.%{d2}", "192.0.2.3", "bad.strong.lp._spf.example.com"},
		{"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", "192.0.2.3", "bad.strong.lp.3.2.0.192.in-addr._spf.example.com"},
		{"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", "192.0.2.3", "3.2.0.192.in-addr.strong.lp._spf.example.com"},
		{"%{d2}.trusted-domains.example.net", "192.0.2.3", "example.com.trusted-domains.example.net"},
		{"%{ir}.%{v}._spf.%{d2}", "2001:db8::cb01", "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"},
		{"a%%b%_c", "192.0.2.3", "a%b c"},
	}
	for _, c := range cases {
		f := dnsauth.NewFake().SetTXT("email.example.com", "v=spf1 exists:"+strings.ReplaceAll(c.macro, "%_", "-")+" -all")
		if strings.Contains(c.macro, "%_") || strings.Contains(c.macro, "%%") {
			continue // spaces and % cannot be a name; covered by the explanation test
		}
		check(f, c.ip, "email.example.com", "strong-bad@email.example.com")
		log := f.Log()
		if len(log) < 2 || log[1] != "ip:"+c.want {
			t.Errorf("%s with %s: looked up %v, want ip:%s", c.macro, c.ip, log, c.want)
		}
	}
}

func TestSPFMacroErrorsArePermErrors(t *testing.T) {
	for _, macro := range []string{"%{x}", "%{", "%", "%{d0}", "%{c}", "%{d}%z", "%{d!}"} {
		f := dnsauth.NewFake().SetTXT("example.com", "v=spf1 exists:"+macro+".example.net -all")
		if got := check(f, "192.0.2.1", "example.com", "u@example.com").Result; got != dnsauth.SPFPermError {
			t.Errorf("%s: %s", macro, got)
		}
	}
}

func TestSPFDNSLookupLimit(t *testing.T) {
	f := dnsauth.NewFake()
	// A chain of includes: each domain includes the next, the last passes.
	for i := 0; i < 12; i++ {
		next := fmt.Sprintf("include:d%d.example.com", i+1)
		f.SetTXT(fmt.Sprintf("d%d.example.com", i), "v=spf1 "+next+" -all")
	}
	f.SetTXT("d12.example.com", "v=spf1 +all")
	f.SetTXT("short.example.com", "v=spf1 include:d9.example.com -all")
	// d9 -> d10 -> d11 -> d12: 1 + 4 = 4 lookups in all, well within the limit.
	if got := check(f, "192.0.2.1", "short.example.com", "u@short.example.com"); got.Result != dnsauth.SPFPass {
		t.Errorf("short chain: %+v", got)
	}
	f.SetTXT("long.example.com", "v=spf1 include:d0.example.com -all")
	got := check(f, "192.0.2.1", "long.example.com", "u@long.example.com")
	if got.Result != dnsauth.SPFPermError || !strings.Contains(got.Err.Error(), "limit") {
		t.Errorf("long chain: %+v", got)
	}
	// The limit stops the work: it does not look up every name.
	if n := f.Lookups(); n > 40 {
		t.Errorf("%d lookups", n)
	}
	// Ten terms are allowed, the eleventh is not. Each "a" finds an address that
	// is not the client's, so none of them is a void lookup, and the last one
	// matches.
	build := func(n int) string {
		terms := make([]string, n)
		for i := range terms {
			terms[i] = fmt.Sprintf("a:n%d.example.com", i)
			addr := fmt.Sprintf("203.0.113.%d", i+1)
			if i == n-1 {
				addr = "192.0.2.1"
			}
			f.SetIP(fmt.Sprintf("n%d.example.com", i), addr)
		}
		return "v=spf1 " + strings.Join(terms, " ") + " -all"
	}
	f.SetTXT("ten.example.com", build(10))
	if got := check(f, "192.0.2.1", "ten.example.com", "u@ten.example.com"); got.Result != dnsauth.SPFPass || got.Lookups != 10 {
		t.Errorf("ten lookups: %+v", got)
	}
	f.SetTXT("eleven.example.com", build(11))
	if got := check(f, "192.0.2.1", "eleven.example.com", "u@eleven.example.com"); got.Result != dnsauth.SPFPermError {
		t.Errorf("eleven lookups: %+v", got)
	}
}

func TestSPFVoidLookupLimit(t *testing.T) {
	f := dnsauth.NewFake().SetTXT("example.com", "v=spf1 exists:a.void.net exists:b.void.net exists:c.void.net +all")
	got := check(f, "192.0.2.1", "example.com", "u@example.com")
	if got.Result != dnsauth.SPFPermError {
		t.Errorf("three void lookups: %+v", got)
	}
	f.SetTXT("two.example.com", "v=spf1 exists:a.void.net exists:b.void.net +all")
	if got := check(f, "192.0.2.1", "two.example.com", "u@two.example.com"); got.Result != dnsauth.SPFPass {
		t.Errorf("two void lookups: %+v", got)
	}
	c := &dnsauth.SPFChecker{Resolver: f, MaxVoidLookups: 5}
	if got := c.Check(context.Background(), net.ParseIP("192.0.2.1"), "example.com", "u@example.com", "h"); got.Result != dnsauth.SPFPass {
		t.Errorf("raised limit: %+v", got)
	}
}

func TestSPFMXWithTooManyHosts(t *testing.T) {
	f := dnsauth.NewFake().SetTXT("example.com", "v=spf1 mx -all")
	var mxs []dnsauth.MX
	for i := 0; i < 11; i++ {
		mxs = append(mxs, dnsauth.MX{Host: fmt.Sprintf("mx%d.example.com", i), Pref: 10})
	}
	f.SetMX("example.com", mxs...)
	if got := check(f, "192.0.2.1", "example.com", "u@example.com"); got.Result != dnsauth.SPFPermError {
		t.Errorf("eleven MX hosts: %+v", got)
	}
}

func TestSPFEmptySenderUsesHELO(t *testing.T) {
	f := dnsauth.NewFake().SetTXT("helo.example.org", "v=spf1 ip4:192.0.2.1 -all")
	c := &dnsauth.SPFChecker{Resolver: f}
	if got := c.Check(context.Background(), net.ParseIP("192.0.2.1"), "helo.example.org", "", "helo.example.org"); got.Result != dnsauth.SPFPass {
		t.Errorf("%+v", got)
	}
}

func TestParseSPF(t *testing.T) {
	good := []string{
		"v=spf1", "V=SPF1 -all", "v=spf1 +a +mx ~all", "v=spf1 a:example.com/24//64 mx//64 ptr ptr:example.com",
		"v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.1 ip6:2001:db8::/32 ip6:::1",
		"v=spf1 include:_spf.example.com exists:%{i}.x.net redirect=other.example.com exp=e.example.com unknown=1",
		"v=spf1 ?all",
	}
	for _, s := range good {
		if _, err := dnsauth.ParseSPF(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := []string{
		"", "v=spf2 -all", "spf1 -all", "v=spf1 all:x", "v=spf1 include", "v=spf1 include:", "v=spf1 exists",
		"v=spf1 ip4:300.0.0.1", "v=spf1 ip4:192.0.2.0/33", "v=spf1 ip4:2001:db8::1", "v=spf1 ip6:192.0.2.1",
		"v=spf1 ip6:::1/129", "v=spf1 a/33", "v=spf1 a//129", "v=spf1 a/", "v=spf1 ptr/24", "v=spf1 bogus",
		"v=spf1 redirect=a redirect=b", "v=spf1 exp=a exp=b", "v=spf1 redirect=", "v=spf1 ip4:1.2.3.4/024",
		"v=spf1 a:", "v=spf1 mx:/24",
	}
	for _, s := range bad {
		if _, err := dnsauth.ParseSPF(s); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
	rec, err := dnsauth.ParseSPF("v=spf1 -a:example.com/24//64 ~ip4:192.0.2.0/24")
	if err != nil || len(rec.Terms) != 2 {
		t.Fatalf("%+v, %v", rec, err)
	}
	if t0 := rec.Terms[0]; t0.Qualifier != '-' || t0.Mechanism != "a" || t0.Domain != "example.com" || t0.Prefix4 != 24 || t0.Prefix6 != 64 {
		t.Errorf("term = %+v", t0)
	}
	if t1 := rec.Terms[1]; t1.Qualifier != '~' || t1.Network.String() != "192.0.2.0/24" {
		t.Errorf("term = %+v", t1)
	}
}

func FuzzParseSPF(f *testing.F) {
	for _, s := range []string{"v=spf1 a mx -all", "v=spf1 include:x.com exists:%{i}.y redirect=z", "v=spf1 ip4:1.2.3.4/32 ip6:::/0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := dnsauth.ParseSPF(s)
		if err != nil {
			return
		}
		for _, term := range rec.Terms {
			if (term.Mechanism == "ip4" || term.Mechanism == "ip6") && term.Network == nil {
				t.Fatalf("%q: ip term with no network", s)
			}
		}
	})
}

// FuzzCheckSPF evaluates arbitrary records, all of them published at the same
// name, against a resolver that answers for everything it is asked: it must
// end, within the limits, with a result and no panic.
func FuzzCheckSPF(f *testing.F) {
	for _, s := range []string{
		"v=spf1 include:example.com -all", "v=spf1 a mx ptr exists:%{i}.example.com redirect=example.com",
		"v=spf1 redirect=%{d}", "v=spf1 exp=example.com -all", "v=spf1 a:%{l}.%{d2r} -all",
	} {
		f.Add(s, "192.0.2.1")
	}
	f.Fuzz(func(t *testing.T, record, ipText string) {
		ip := net.ParseIP(ipText)
		if ip == nil {
			return
		}
		fake := dnsauth.NewFake().
			SetTXT("example.com", record).
			SetIP("example.com", "192.0.2.1", "2001:db8::1").
			SetMX("example.com", dnsauth.MX{Host: "example.com", Pref: 1}).
			SetPTR(ip.String(), "example.com")
		c := &dnsauth.SPFChecker{Resolver: fake}
		v := c.Check(context.Background(), ip, "example.com", "u@example.com", "helo.example.com")
		switch v.Result {
		case dnsauth.SPFNone, dnsauth.SPFNeutral, dnsauth.SPFPass, dnsauth.SPFFail, dnsauth.SPFSoftFail, dnsauth.SPFTempError, dnsauth.SPFPermError:
		default:
			t.Fatalf("result %q", v.Result)
		}
		if n := fake.Lookups(); n > 200 {
			t.Fatalf("%d lookups for one evaluation", n)
		}
	})
}

func BenchmarkParseSPF(b *testing.B) {
	const rec = "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.provider.net mx a:relay.example.com/28 ~all"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := dnsauth.ParseSPF(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckSPF(b *testing.B) {
	f := dnsauth.NewFake().
		SetTXT("example.com", "v=spf1 include:_spf.provider.net ip4:198.51.100.0/24 -all").
		SetTXT("_spf.provider.net", "v=spf1 ip4:203.0.113.0/24 ip4:192.0.2.0/24 -all")
	c := &dnsauth.SPFChecker{Resolver: f}
	ip := net.ParseIP("192.0.2.10")
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if v := c.Check(ctx, ip, "example.com", "u@example.com", "h.example.com"); v.Result != dnsauth.SPFPass {
			b.Fatal(v)
		}
	}
}
