package dnsauth_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hyz-is/arandu-mail/dnsauth"
)

func TestParseDMARC(t *testing.T) {
	rec, err := dnsauth.ParseDMARC("v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=r; pct=25; rua=mailto:a@x.com, mailto:b@x.com; ruf=mailto:f@x.com; fo=1; ri=3600")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Policy != dnsauth.DispositionQuarantine || rec.SubdomainPolicy != dnsauth.DispositionReject ||
		rec.ADKIM != 's' || rec.ASPF != 'r' || rec.Percent != 25 || len(rec.RUA) != 2 || len(rec.RUF) != 1 ||
		rec.FailureOptions != "1" || rec.ReportInterval != 3600 {
		t.Errorf("record = %+v", rec)
	}
	def, err := dnsauth.ParseDMARC("v=DMARC1; p=none;")
	if err != nil || def.ADKIM != 'r' || def.ASPF != 'r' || def.Percent != 100 || def.ReportInterval != 86400 || def.FailureOptions != "0" {
		t.Errorf("defaults = %+v, %v", def, err)
	}
	// No p= but a rua= is read as p=none.
	if rec, err := dnsauth.ParseDMARC("v=DMARC1; rua=mailto:a@x.com"); err != nil || rec.Policy != dnsauth.DispositionNone {
		t.Errorf("monitoring record: %+v, %v", rec, err)
	}
	for _, bad := range []string{
		"", "p=none", "v=DMARC2; p=none", "v=DMARC1", "v=DMARC1; p=bogus", "v=DMARC1; p=none; pct=101",
		"v=DMARC1; p=none; pct=x", "v=DMARC1; p=none; adkim=x", "v=DMARC1; p=none; junk", "v=DMARC1; sp=none",
		"v=DMARC1; p=none; ri=-1",
	} {
		if _, err := dnsauth.ParseDMARC(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAlignment(t *testing.T) {
	cases := []struct {
		from, auth   string
		strict, want bool
	}{
		{"example.com", "example.com", true, true},
		{"example.com", "EXAMPLE.com.", true, true},
		{"example.com", "mail.example.com", true, false},
		{"example.com", "mail.example.com", false, true},
		{"news.example.com", "mail.example.com", false, true},
		{"news.example.com", "mail.example.com", true, false},
		{"example.com", "example.org", false, false},
		{"a.example.co.uk", "b.example.co.uk", false, true},
		{"a.example.co.uk", "b.other.co.uk", false, false},
		{"example.co.uk", "other.co.uk", false, false},
		{"a.github.io", "b.github.io", false, false}, // github.io is on the public suffix list
		{"", "example.com", false, false},
		{"example.com", "", false, false},
	}
	for _, c := range cases {
		if got := dnsauth.Aligned(c.from, c.auth, c.strict); got != c.want {
			t.Errorf("Aligned(%q, %q, strict=%v) = %v", c.from, c.auth, c.strict, got)
		}
	}
	if got := dnsauth.OrganizationalDomain("Mail.Example.CO.UK."); got != "example.co.uk" {
		t.Errorf("OrganizationalDomain = %q", got)
	}
}

func TestLookupAndEvaluateDMARC(t *testing.T) {
	f := dnsauth.NewFake().
		SetTXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine; adkim=s").
		SetTXT("_dmarc.two.org", "v=DMARC1; p=none", "v=DMARC1; p=reject").
		SetTXT("_dmarc.junk.org", "v=DMARC1; p=bogus").
		SetError("txt", "_dmarc.down.org", errors.New("timeout"))
	ctx := context.Background()

	rec, at, err := dnsauth.LookupDMARC(ctx, f, "example.com")
	if err != nil || rec == nil || at != "example.com" {
		t.Fatalf("%+v %q %v", rec, at, err)
	}
	// A subdomain with no record of its own falls back to the organizational one.
	rec, at, err = dnsauth.LookupDMARC(ctx, f, "news.example.com")
	if err != nil || rec == nil || at != "example.com" {
		t.Fatalf("%+v %q %v", rec, at, err)
	}
	for _, d := range []string{"nothing.net", "two.org", "junk.org"} {
		if rec, _, err := dnsauth.LookupDMARC(ctx, f, d); rec != nil || err != nil {
			t.Errorf("%s: %+v %v", d, rec, err)
		}
	}
	if _, _, err := dnsauth.LookupDMARC(ctx, f, "down.org"); err == nil {
		t.Error("a DNS failure was swallowed")
	}

	spfPass := dnsauth.SPFOutcome{Result: dnsauth.SPFPass, Domain: "mail.example.com"}
	cases := []struct {
		name  string
		in    dnsauth.DMARCInput
		pass  bool
		spf   bool
		dkim  bool
		apply dnsauth.Disposition
	}{
		{"spf aligned relaxed", dnsauth.DMARCInput{FromDomain: "example.com", SPF: spfPass}, true, true, false, dnsauth.DispositionReject},
		{"dkim strict aligned", dnsauth.DMARCInput{FromDomain: "example.com", DKIM: []dnsauth.DKIMOutcome{{Pass: true, Domain: "example.com"}}}, true, false, true, dnsauth.DispositionReject},
		{"dkim strict, relaxed domain", dnsauth.DMARCInput{FromDomain: "example.com", DKIM: []dnsauth.DKIMOutcome{{Pass: true, Domain: "mail.example.com"}}}, false, false, false, dnsauth.DispositionReject},
		{"dkim failed", dnsauth.DMARCInput{FromDomain: "example.com", DKIM: []dnsauth.DKIMOutcome{{Pass: false, Domain: "example.com"}}}, false, false, false, dnsauth.DispositionReject},
		{"spf not pass", dnsauth.DMARCInput{FromDomain: "example.com", SPF: dnsauth.SPFOutcome{Result: dnsauth.SPFSoftFail, Domain: "example.com"}}, false, false, false, dnsauth.DispositionReject},
		{"subdomain uses sp", dnsauth.DMARCInput{FromDomain: "news.example.com", SPF: spfPass}, true, true, false, dnsauth.DispositionQuarantine},
		{"other domain spf", dnsauth.DMARCInput{FromDomain: "example.com", SPF: dnsauth.SPFOutcome{Result: dnsauth.SPFPass, Domain: "example.org"}}, false, false, false, dnsauth.DispositionReject},
	}
	for _, c := range cases {
		res, err := dnsauth.EvaluateDMARC(ctx, f, c.in)
		if err != nil || !res.HasPolicy {
			t.Fatalf("%s: %+v %v", c.name, res, err)
		}
		if res.Pass != c.pass || res.SPFAligned != c.spf || res.DKIMAligned != c.dkim || res.Policy != c.apply {
			t.Errorf("%s: %+v", c.name, res)
		}
	}
	if res, err := dnsauth.EvaluateDMARC(ctx, f, dnsauth.DMARCInput{FromDomain: "nothing.net"}); err != nil || res.HasPolicy || res.Pass {
		t.Errorf("no policy: %+v %v", res, err)
	}
	if _, err := dnsauth.EvaluateDMARC(ctx, f, dnsauth.DMARCInput{FromDomain: "down.org"}); err == nil {
		t.Error("a DNS failure was swallowed")
	}
}

const goodPolicy = "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmx: backupmx.example.com\r\nmax_age: 604800\r\n"

func TestParseMTASTSPolicy(t *testing.T) {
	p, err := dnsauth.ParseMTASTSPolicy([]byte(goodPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if p.Mode != dnsauth.MTASTSEnforce || p.MaxAge != 604800 || len(p.MX) != 3 {
		t.Errorf("policy = %+v", p)
	}
	back, err := dnsauth.ParseMTASTSPolicy([]byte(p.String()))
	if err != nil || back.String() != p.String() {
		t.Errorf("String does not round trip: %v", err)
	}
	if _, err := dnsauth.ParseMTASTSPolicy([]byte("version: STSv1\nmode: none\nmax_age: 0\n")); err != nil {
		t.Errorf("mode none needs no mx: %v", err)
	}
	for _, bad := range []string{
		"", "mode: enforce\nmx: a.b\nmax_age: 1", "version: STSv2\nmode: enforce\nmx: a.b\nmax_age: 1",
		"version: STSv1\nmode: nope\nmx: a.b\nmax_age: 1", "version: STSv1\nmode: enforce\nmax_age: 1",
		"version: STSv1\nmode: enforce\nmx: a.b", "version: STSv1\nmode: enforce\nmx: a.b\nmax_age: x",
		"version: STSv1\nmode: enforce\nmx: a.b\nmax_age: 99999999999", "version: STSv1\nnot a line",
	} {
		if _, err := dnsauth.ParseMTASTSPolicy([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for host, want := range map[string]bool{
		"mail.example.com": true, "MAIL.example.com.": true, "other.example.com": false,
		"a.example.net": true, "a.b.example.net": false, "example.net": false, "backupmx.example.com": true,
		"evilexample.net": false,
	} {
		if got := p.MatchMX(host); got != want {
			t.Errorf("MatchMX(%q) = %v", host, got)
		}
	}
}

type fakeHTTP func(*http.Request) (*http.Response, error)

func (f fakeHTTP) Do(r *http.Request) (*http.Response, error) { return f(r) }

func reply(status int, contentType, body string) fakeHTTP {
	return func(r *http.Request) (*http.Response, error) {
		h := http.Header{}
		if contentType != "" {
			h.Set("Content-Type", contentType)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	}
}

func TestLookupMTASTS(t *testing.T) {
	f := dnsauth.NewFake().
		SetTXT("_mta-sts.example.com", "v=STSv1; id=20261120T000000").
		SetTXT("_mta-sts.bad.org", "v=STSv1; id=has space").
		SetTXT("_mta-sts.two.org", "v=STSv1; id=a", "v=STSv1; id=b")
	ctx := context.Background()
	var asked string
	client := fakeHTTP(func(r *http.Request) (*http.Response, error) {
		asked = r.URL.String()
		return reply(200, "text/plain; charset=utf-8", goodPolicy)(r)
	})
	res, err := dnsauth.LookupMTASTS(ctx, f, client, "Example.com")
	if err != nil || res.ID != "20261120T000000" || res.Policy.Mode != dnsauth.MTASTSEnforce {
		t.Fatalf("%+v %v", res, err)
	}
	if asked != "https://mta-sts.example.com/.well-known/mta-sts.txt" {
		t.Errorf("fetched %q", asked)
	}
	if _, err := dnsauth.LookupMTASTS(ctx, f, client, "nothing.net"); !errors.Is(err, dnsauth.ErrNoMTASTS) {
		t.Errorf("no record: %v", err)
	}
	for _, d := range []string{"bad.org", "two.org"} {
		if _, err := dnsauth.LookupMTASTS(ctx, f, client, d); !errors.Is(err, dnsauth.ErrMTASTSSyntax) {
			t.Errorf("%s: %v", d, err)
		}
	}
	for name, c := range map[string]fakeHTTP{
		"not found":    reply(404, "text/plain", ""),
		"redirect":     reply(301, "text/plain", ""),
		"content type": reply(200, "text/html", goodPolicy),
		"no type":      reply(200, "", goodPolicy),
		"too big":      reply(200, "text/plain", strings.Repeat("x", dnsauth.MaxPolicySize+1)),
		"garbage":      reply(200, "text/plain", "hello"),
		"network":      func(*http.Request) (*http.Response, error) { return nil, errors.New("connection refused") },
	} {
		if _, err := dnsauth.LookupMTASTS(ctx, f, c, "example.com"); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if dnsauth.MTASTSRecord("abc") != "v=STSv1; id=abc" {
		t.Error("MTASTSRecord")
	}
	if c := dnsauth.NewHTTPClient(0); c.Timeout != 60*time.Second || c.CheckRedirect == nil {
		t.Error("NewHTTPClient must set a timeout and refuse redirects")
	}
}

func TestTLSRPT(t *testing.T) {
	rec, err := dnsauth.ParseTLSRPT("v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tlsrpt")
	if err != nil || len(rec.RUA) != 2 {
		t.Fatalf("%+v %v", rec, err)
	}
	for _, bad := range []string{"", "v=TLSRPTv1", "v=TLSRPTv2; rua=mailto:a@b.c", "v=TLSRPTv1; rua=ftp://x", "v=TLSRPTv1; rua=mailto:"} {
		if _, err := dnsauth.ParseTLSRPT(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	f := dnsauth.NewFake().
		SetTXT("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls@example.com").
		SetTXT("_smtp._tls.two.org", "v=TLSRPTv1; rua=mailto:a@b.c", "v=TLSRPTv1; rua=mailto:d@e.f")
	if rec, err := dnsauth.LookupTLSRPT(context.Background(), f, "example.com"); err != nil || rec.RUA[0] != "mailto:tls@example.com" {
		t.Errorf("%+v %v", rec, err)
	}
	if _, err := dnsauth.LookupTLSRPT(context.Background(), f, "nothing.net"); !errors.Is(err, dnsauth.ErrNoTLSRPT) {
		t.Errorf("no record: %v", err)
	}
	if _, err := dnsauth.LookupTLSRPT(context.Background(), f, "two.org"); err == nil {
		t.Error("two records accepted")
	}
}

func FuzzParseDMARC(f *testing.F) {
	for _, s := range []string{"v=DMARC1; p=none", "v=DMARC1; p=reject; pct=50; rua=mailto:a@b.c", ";;;", "v=DMARC1;p="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := dnsauth.ParseDMARC(s)
		if err == nil && rec.Policy == "" {
			t.Fatalf("%q: accepted without a policy", s)
		}
	})
}

func FuzzParseMTASTSPolicy(f *testing.F) {
	f.Add([]byte(goodPolicy))
	f.Add([]byte("version: STSv1\nmode: none\nmax_age: 0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := dnsauth.ParseMTASTSPolicy(b)
		if err != nil {
			return
		}
		if _, err := dnsauth.ParseMTASTSPolicy([]byte(p.String())); err != nil {
			t.Fatalf("a parsed policy does not parse again: %v\n%q", err, p.String())
		}
		_ = p.MatchMX("mx.example.com")
	})
}

func FuzzParseTLSRPT(f *testing.F) {
	f.Add("v=TLSRPTv1; rua=mailto:a@b.c")
	f.Fuzz(func(t *testing.T, s string) { _, _ = dnsauth.ParseTLSRPT(s) })
}
