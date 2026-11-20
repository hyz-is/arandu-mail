package dnsauth_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/dnsauth"
)

const dkimKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB"

func config(domain string) dnsauth.Config {
	return dnsauth.Config{
		Domain: domain, DKIMSelector: "meeng", DKIMPublicKey: dkimKey,
		InboundHost: "inbound.meeng.dev", SPFMechanisms: []string{"include:spf.meeng.dev"},
	}
}

func TestRecordsHaveTheLayoutOfTheDashboard(t *testing.T) {
	recs, err := dnsauth.Records(config("acme.com"))
	if err != nil {
		t.Fatal(err)
	}
	want := []dnsauth.Record{
		{Purpose: dnsauth.PurposeMX, Type: "MX", Name: "mail", FQDN: "mail.acme.com", Value: "inbound.meeng.dev", TTL: "Auto", Priority: "10", Status: dnsauth.NotStarted},
		{Purpose: dnsauth.PurposeDKIM, Type: "TXT", Name: "meeng._domainkey", FQDN: "meeng._domainkey.acme.com", Value: "p=" + dkimKey, TTL: "Auto", Status: dnsauth.NotStarted},
		{Purpose: dnsauth.PurposeSPF, Type: "TXT", Name: "mail", FQDN: "mail.acme.com", Value: "v=spf1 include:spf.meeng.dev ~all", TTL: "Auto", Status: dnsauth.NotStarted},
		{Purpose: dnsauth.PurposeDMARC, Type: "TXT", Name: "_dmarc", FQDN: "_dmarc.acme.com", Value: "v=DMARC1; p=none;", TTL: "Auto", Status: dnsauth.NotStarted, Recommended: true},
	}
	if len(recs) != len(want) {
		t.Fatalf("%d records", len(recs))
	}
	for i := range want {
		if recs[i] != want[i] {
			t.Errorf("record %d:\n got %+v\nwant %+v", i, recs[i], want[i])
		}
	}
}

func TestRecordsForASubdomain(t *testing.T) {
	recs, err := dnsauth.Records(config("send.acme.co.uk"))
	if err != nil {
		t.Fatal(err)
	}
	names := map[dnsauth.Purpose][2]string{}
	for _, r := range recs {
		names[r.Purpose] = [2]string{r.Name, r.FQDN}
	}
	want := map[dnsauth.Purpose][2]string{
		dnsauth.PurposeMX:    {"mail.send", "mail.send.acme.co.uk"},
		dnsauth.PurposeSPF:   {"mail.send", "mail.send.acme.co.uk"},
		dnsauth.PurposeDKIM:  {"meeng._domainkey.send", "meeng._domainkey.send.acme.co.uk"},
		dnsauth.PurposeDMARC: {"_dmarc", "_dmarc.acme.co.uk"}, // DMARC sits at the zone, as in useSend
	}
	for p, w := range want {
		if names[p] != w {
			t.Errorf("%s: %v, want %v", p, names[p], w)
		}
	}
}

func TestRecordsOptions(t *testing.T) {
	cfg := config("Bücher.example")
	cfg.DKIMKeyType = "ed25519"
	cfg.MailFromSubdomain = "bounce"
	cfg.MXPriority = 5
	cfg.SPFMechanisms = []string{"ip4:192.0.2.0/24", "include:spf.meeng.dev"}
	cfg.SPFAll = "-all"
	cfg.DMARC = "v=DMARC1; p=reject; rua=mailto:d@example.com"
	cfg.TTL = "3600"
	recs, err := dnsauth.Records(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].Name != "bounce" || recs[0].FQDN != "bounce.xn--bcher-kva.example" || recs[0].Priority != "5" || recs[0].TTL != "3600" {
		t.Errorf("MX = %+v", recs[0])
	}
	if recs[1].Value != "v=DKIM1; k=ed25519; p="+dkimKey {
		t.Errorf("DKIM = %q", recs[1].Value)
	}
	if recs[2].Value != "v=spf1 ip4:192.0.2.0/24 include:spf.meeng.dev -all" || recs[3].Value != cfg.DMARC {
		t.Errorf("SPF %q DMARC %q", recs[2].Value, recs[3].Value)
	}
}

func TestRecordsRefuseABadConfig(t *testing.T) {
	bad := map[string]func(*dnsauth.Config){
		"no domain":     func(c *dnsauth.Config) { c.Domain = "" },
		"public suffix": func(c *dnsauth.Config) { c.Domain = "co.uk" },
		"no key":        func(c *dnsauth.Config) { c.DKIMPublicKey = "" },
		"no host":       func(c *dnsauth.Config) { c.InboundHost = "" },
		"no spf":        func(c *dnsauth.Config) { c.SPFMechanisms = nil },
		"bad spf":       func(c *dnsauth.Config) { c.SPFMechanisms = []string{"bogus:x"} },
	}
	for name, mutate := range bad {
		c := config("acme.com")
		mutate(&c)
		if _, err := dnsauth.Records(c); !errors.Is(err, dnsauth.ErrConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func publishAll(f *dnsauth.Fake, recs []dnsauth.Record) {
	for _, r := range recs {
		if r.Type == "MX" {
			f.SetMX(r.FQDN, dnsauth.MX{Host: r.Value, Pref: 10})
		} else {
			f.SetTXT(r.FQDN, r.Value)
		}
	}
}

func statuses(recs []dnsauth.Record) map[dnsauth.Purpose]dnsauth.Status {
	out := map[dnsauth.Purpose]dnsauth.Status{}
	for _, r := range recs {
		out[r.Purpose] = r.Status
	}
	return out
}

func TestVerifyEverythingPublished(t *testing.T) {
	recs, _ := dnsauth.Records(config("acme.com"))
	f := dnsauth.NewFake()
	publishAll(f, recs)
	got := dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{})
	for p, s := range statuses(got) {
		if s != dnsauth.Success {
			t.Errorf("%s: %s", p, s)
		}
	}
	if dnsauth.Overall(got) != dnsauth.Success {
		t.Errorf("overall = %s", dnsauth.Overall(got))
	}
	if recs[0].Status != dnsauth.NotStarted {
		t.Error("Verify changed its input")
	}
}

func TestVerifyNothingPublished(t *testing.T) {
	recs, _ := dnsauth.Records(config("acme.com"))
	got := dnsauth.Verify(context.Background(), dnsauth.NewFake(), recs, dnsauth.VerifyOptions{})
	want := map[dnsauth.Purpose]dnsauth.Status{
		dnsauth.PurposeMX: dnsauth.Pending, dnsauth.PurposeDKIM: dnsauth.Pending,
		dnsauth.PurposeSPF: dnsauth.Pending, dnsauth.PurposeDMARC: dnsauth.NotStarted,
	}
	for p, s := range statuses(got) {
		if s != want[p] {
			t.Errorf("%s: %s, want %s", p, s, want[p])
		}
	}
	if dnsauth.Overall(got) != dnsauth.Pending {
		t.Errorf("overall = %s", dnsauth.Overall(got))
	}
	// Once the time allowed has run out, the missing records fail.
	late := dnsauth.Verify(context.Background(), dnsauth.NewFake(), recs, dnsauth.VerifyOptions{FailMissing: true})
	if dnsauth.Overall(late) != dnsauth.Failed || late[0].Status != dnsauth.Failed {
		t.Errorf("late: %+v", statuses(late))
	}
}

func TestVerifyWrongValues(t *testing.T) {
	recs, _ := dnsauth.Records(config("acme.com"))
	f := dnsauth.NewFake().
		SetTXT("meeng._domainkey.acme.com", "p=OTHERKEY").
		SetTXT("mail.acme.com", "v=spf1 include:other.example ~all").
		SetMX("mail.acme.com", dnsauth.MX{Host: "mx.other.example", Pref: 10}).
		SetTXT("_dmarc.acme.com", "v=DMARC1; p=bogus")
	got := statuses(dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{}))
	for p, s := range got {
		if s != dnsauth.Failed {
			t.Errorf("%s: %s, want FAILED", p, s)
		}
	}
}

func TestVerifyAcceptsMoreThanAskedAndRejectsLess(t *testing.T) {
	recs, _ := dnsauth.Records(config("acme.com"))
	f := dnsauth.NewFake().
		SetTXT("meeng._domainkey.acme.com", "v=DKIM1; k=rsa; p="+dkimKey[:50]+" "+dkimKey[50:]).
		SetTXT("mail.acme.com", "v=spf1 ip4:192.0.2.1 include:spf.meeng.dev include:other.net -all").
		SetMX("mail.acme.com", dnsauth.MX{Host: "inbound.meeng.dev", Pref: 10}, dnsauth.MX{Host: "backup.example.net", Pref: 20})
	got := statuses(dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{}))
	for _, p := range []dnsauth.Purpose{dnsauth.PurposeDKIM, dnsauth.PurposeSPF, dnsauth.PurposeMX} {
		if got[p] != dnsauth.Success {
			t.Errorf("%s: %s", p, got[p])
		}
	}
	// A better MX that is not ours takes the mail: that is a failure.
	f.SetMX("mail.acme.com", dnsauth.MX{Host: "inbound.meeng.dev", Pref: 10}, dnsauth.MX{Host: "mx.other.example", Pref: 5})
	if got := statuses(dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{})); got[dnsauth.PurposeMX] != dnsauth.Failed {
		t.Errorf("MX behind another: %s", got[dnsauth.PurposeMX])
	}
	// Two SPF records are an error in themselves.
	f.SetTXT("mail.acme.com", "v=spf1 include:spf.meeng.dev ~all", "v=spf1 -all")
	if got := statuses(dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{})); got[dnsauth.PurposeSPF] != dnsauth.Failed {
		t.Errorf("two SPF: %s", got[dnsauth.PurposeSPF])
	}
}

func TestVerifyDNSFailure(t *testing.T) {
	recs, _ := dnsauth.Records(config("acme.com"))
	f := dnsauth.NewFake().
		SetError("txt", "meeng._domainkey.acme.com", errors.New("servfail")).
		SetError("mx", "mail.acme.com", &net.DNSError{Err: "timeout", IsTimeout: true})
	got := dnsauth.Verify(context.Background(), f, recs, dnsauth.VerifyOptions{})
	s := statuses(got)
	if s[dnsauth.PurposeDKIM] != dnsauth.TemporaryFailure || s[dnsauth.PurposeMX] != dnsauth.TemporaryFailure {
		t.Errorf("statuses = %v", s)
	}
	if dnsauth.Overall(got) != dnsauth.TemporaryFailure {
		t.Errorf("overall = %s", dnsauth.Overall(got))
	}
}

func TestOverall(t *testing.T) {
	mk := func(ss ...dnsauth.Status) []dnsauth.Record {
		var out []dnsauth.Record
		for _, s := range ss {
			out = append(out, dnsauth.Record{Status: s})
		}
		return append(out, dnsauth.Record{Status: dnsauth.Failed, Recommended: true})
	}
	cases := []struct {
		in   []dnsauth.Status
		want dnsauth.Status
	}{
		{[]dnsauth.Status{dnsauth.Success, dnsauth.Success, dnsauth.Success}, dnsauth.Success},
		{[]dnsauth.Status{dnsauth.Success, dnsauth.Pending, dnsauth.Success}, dnsauth.Pending},
		{[]dnsauth.Status{dnsauth.Success, dnsauth.Failed, dnsauth.TemporaryFailure}, dnsauth.Failed},
		{[]dnsauth.Status{dnsauth.Success, dnsauth.TemporaryFailure, dnsauth.Pending}, dnsauth.TemporaryFailure},
		{[]dnsauth.Status{dnsauth.NotStarted, dnsauth.NotStarted, dnsauth.NotStarted}, dnsauth.NotStarted},
		{nil, dnsauth.NotStarted},
	}
	for _, c := range cases {
		if got := dnsauth.Overall(mk(c.in...)); got != c.want {
			t.Errorf("%v = %s, want %s", c.in, got, c.want)
		}
	}
	if !strings.HasPrefix(string(dnsauth.TemporaryFailure), "TEMPORARY") {
		t.Error("status names")
	}
}
