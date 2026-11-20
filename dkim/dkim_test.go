package dkim_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hyz-is/arandu-mail/dkim"
)

// The keys and the DNS records of RFC 8463 appendix A.
const (
	rfcEd25519Seed = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A="
	rfcRSAKey      = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQi
Y/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqM
KrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB
AoGAH0cxOhFZDgzXWhDhnAJDw5s4roOXN4OhjiXa8W7Y3rhX3FJqmJSPuC8N9vQm
6SVbaLAE4SG5mLMueHlh4KXffEpuLEiNp9Ss3O4YfLiQpbRqE7Tm5SxKjvvQoZZe
zHorimOaChRL2it47iuWxzxSiRMv4c+j70GiWdxXnxe4UoECQQDzJB/0U58W7RZy
6enGVj2kWF732CoWFZWzi1FicudrBFoy63QwcowpoCazKtvZGMNlPWnC7x/6o8Gc
uSe0ga2xAkEA8C7PipPm1/1fTRQvj1o/dDmZp243044ZNyxjg+/OPN0oWCbXIGxy
WvmZbXriOWoSALJTjExEgraHEgnXssuk7QJBALl5ICsYMu6hMxO73gnfNayNgPxd
WFV6Z7ULnKyV7HSVYF0hgYOHjeYe9gaMtiJYoo0zGN+L3AAtNP9huqkWlzECQE1a
licIeVlo1e+qJ6Mgqr0Q7Aa7falZ448ccbSFYEPD6oFxiOl9Y9se9iYHZKKfIcst
o7DUw1/hz2Ck4N5JrgUCQQCyKveNvjzkkd8HjYs0SwM0fPjK16//5qDZ2UiDGnOe
uEzxBDAr518Z8VFbR41in3W4Y3yCDgQlLlcETrS+zYcL
-----END RSA PRIVATE KEY-----
`
	rfcEd25519Record = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
	rfcRSARecord     = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" +
		"iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" +
		"DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" +
		"Ip3G+2kryOTIKT+l/K4w3QIDAQAB"
)

type fakeDNS map[string][]string

func (f fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[strings.ToLower(name)]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

type brokenDNS struct{}

func (brokenDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
}

func rfcDNS() fakeDNS {
	return fakeDNS{
		"brisbane._domainkey.football.example.com": {rfcEd25519Record},
		"test._domainkey.football.example.com":     {rfcRSARecord},
	}
}

func readFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifiesTheSignaturesOfRFC8463(t *testing.T) {
	msg := readFile(t, "rfc8463-signed.eml")
	v := &dkim.Verifier{Resolver: rfcDNS()}
	results := v.Verify(context.Background(), msg)
	if len(results) != 2 {
		t.Fatalf("%d results, want 2", len(results))
	}
	want := []struct {
		alg      dkim.Algorithm
		selector string
	}{{dkim.Ed25519SHA256, "brisbane"}, {dkim.RSASHA256, "test"}}
	for i, r := range results {
		if r.Status != dkim.Pass {
			t.Errorf("signature %d: %s, %v", i, r.Status, r.Err)
		}
		if r.Algorithm != want[i].alg || r.Selector != want[i].selector || r.Domain != "football.example.com" {
			t.Errorf("signature %d = %+v", i, r)
		}
		if r.HeaderCanon != dkim.Relaxed || r.BodyCanon != dkim.Relaxed {
			t.Errorf("signature %d canonicalization %s/%s", i, r.HeaderCanon, r.BodyCanon)
		}
	}
}

func TestTheRFC8463SignaturesBreakWhenTheMessageChanges(t *testing.T) {
	msg := readFile(t, "rfc8463-signed.eml")
	mutations := map[string]func([]byte) []byte{
		"body":          func(b []byte) []byte { return bytes.Replace(b, []byte("hungry"), []byte("angry"), 1) },
		"subject":       func(b []byte) []byte { return bytes.Replace(b, []byte("dinner"), []byte("lunch"), 1) },
		"extra from":    func(b []byte) []byte { return append([]byte("From: evil@example.org\r\n"), b...) },
		"extra subject": func(b []byte) []byte { return append([]byte("Subject: spoof\r\n"), b...) },
		"removed header": func(b []byte) []byte {
			return bytes.Replace(b, []byte("Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n"), nil, 1)
		},
	}
	v := &dkim.Verifier{Resolver: rfcDNS()}
	for name, mutate := range mutations {
		for i, r := range v.Verify(context.Background(), mutate(msg)) {
			if r.Status != dkim.Fail {
				t.Errorf("%s: signature %d is %s (%v), want fail", name, i, r.Status, r.Err)
			}
		}
	}
	// Whitespace the relaxed canonicalization ignores does not break it.
	rewrapped := bytes.Replace(msg, []byte("Subject: Is dinner ready?"), []byte("Subject:  Is   dinner\r\n\tready?  "), 1)
	for i, r := range v.Verify(context.Background(), rewrapped) {
		if r.Status != dkim.Pass {
			t.Errorf("rewrapped: signature %d is %s: %v", i, r.Status, r.Err)
		}
	}
}

func TestRFC8463KeysAreTheOnesThePackageReads(t *testing.T) {
	seed, _ := base64.StdEncoding.DecodeString(rfcEd25519Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if !strings.HasSuffix(rfcEd25519Record, "p="+pub) {
		t.Errorf("seed gives public key %s", pub)
	}
	kp, err := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	if err != nil || kp.Algorithm != dkim.RSASHA256 {
		t.Fatalf("%v %v", kp, err)
	}
	txt, err := kp.TXT()
	if err != nil || txt != rfcRSARecord {
		t.Errorf("TXT = %q, %v", txt, err)
	}
}

func signAndVerify(t *testing.T, key *dkim.KeyPair, hc, bc dkim.Canon, mutate func([]byte) []byte) []dkim.Result {
	t.Helper()
	signer, err := dkim.NewSigner(dkim.Config{
		Domain: "football.example.com", Selector: "s1", Key: key.Signer, HeaderCanon: hc, BodyCanon: bc,
		Now: func() time.Time { return time.Unix(1528637909, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	msg := readFile(t, "rfc8463-unsigned.eml")
	signed, err := signer.SignMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(signed, msg) || !bytes.HasPrefix(signed, []byte("DKIM-Signature: v=1; a="+string(key.Algorithm))) {
		t.Fatalf("SignMessage did not prepend the signature:\n%s", signed)
	}
	for _, line := range bytes.Split(signed, []byte("\r\n")) {
		if len(line) > 78 {
			t.Errorf("line of %d characters: %q", len(line), line)
		}
	}
	txt, err := key.TXT()
	if err != nil {
		t.Fatal(err)
	}
	v := &dkim.Verifier{Resolver: fakeDNS{"s1._domainkey.football.example.com": {txt}},
		Now: func() time.Time { return time.Unix(1528637909, 0) }}
	if mutate != nil {
		signed = mutate(signed)
	}
	return v.Verify(context.Background(), signed)
}

func TestSignedMessagesVerifyInEveryCanonicalization(t *testing.T) {
	rsaKey, err := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := base64.StdEncoding.DecodeString(rfcEd25519Seed)
	edKey, err := dkim.KeyPairFrom(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []*dkim.KeyPair{rsaKey, edKey} {
		for _, hc := range []dkim.Canon{dkim.Simple, dkim.Relaxed} {
			for _, bc := range []dkim.Canon{dkim.Simple, dkim.Relaxed} {
				res := signAndVerify(t, key, hc, bc, nil)
				if len(res) != 1 || res[0].Status != dkim.Pass {
					t.Errorf("%s %s/%s: %+v", key.Algorithm, hc, bc, res)
				}
			}
		}
	}
}

func TestOversigningRejectsAddedHeaders(t *testing.T) {
	rsaKey, _ := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	add := func(h string) func([]byte) []byte {
		return func(b []byte) []byte { return append([]byte(h+"\r\n"), b...) }
	}
	for _, h := range []string{"From: evil@example.org", "To: evil@example.org", "Subject: other"} {
		res := signAndVerify(t, rsaKey, dkim.Relaxed, dkim.Relaxed, add(h))
		// The DKIM-Signature moves below the added field, so the verifier still
		// finds it; the extra instance is what makes the hash differ.
		if len(res) != 1 || res[0].Status != dkim.Fail {
			t.Errorf("%q: %+v", h, res)
		}
	}
	// An unsigned header such as Received may be added without harm.
	if res := signAndVerify(t, rsaKey, dkim.Relaxed, dkim.Relaxed, add("Received: from relay")); res[0].Status != dkim.Pass {
		t.Errorf("an added Received broke the signature: %+v", res[0])
	}
}

func TestSignatureLayout(t *testing.T) {
	key, _ := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	signer, err := dkim.NewSigner(dkim.Config{Domain: "Football.Example.com.", Selector: "s1", Key: key.Signer,
		Identity: "@football.example.com", Expiration: time.Hour,
		Now: func() time.Time { return time.Unix(1528637909, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(readFile(t, "rfc8463-unsigned.eml"))
	if err != nil {
		t.Fatal(err)
	}
	unfolded := strings.NewReplacer("\r\n\t", " ").Replace(string(sig))
	for _, want := range []string{
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=football.example.com; s=s1;",
		"i=@football.example.com;", "t=1528637909;", "x=1528641509;",
		"h=", "bh=",
		"bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;", " b=",
	} {
		if !strings.Contains(unfolded, want) {
			t.Errorf("signature lacks %q:\n%s", want, sig)
		}
	}
	// From, To and Subject are oversigned: each appears one time more than the
	// message has it. The message has one of each.
	h := strings.ReplaceAll(between(unfolded, " h=", ";"), " ", "")
	for _, name := range []string{"from", "to", "subject"} {
		if got := countOf(strings.Split(h, ":"), name); got != 2 {
			t.Errorf("%s appears %d times in h=%s, want 2", name, got, h)
		}
	}
	// Headers the message lacks are not listed, unless oversigned.
	if strings.Contains(h, "cc") || strings.Contains(h, "reply-to") {
		t.Errorf("h= lists absent fields: %s", h)
	}
	if !bytes.HasSuffix(sig, []byte("\r\n")) || bytes.Count(sig, []byte("\r\n")) < 2 {
		t.Errorf("signature is not folded and terminated: %q", sig)
	}
}

func between(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	s = s[i+len(from):]
	j := strings.Index(s, to)
	if j < 0 {
		return s
	}
	return s[:j]
}

func TestExplicitHeaderListReproducesTheRFCOversigning(t *testing.T) {
	seed, _ := base64.StdEncoding.DecodeString(rfcEd25519Seed)
	signer, err := dkim.NewSigner(dkim.Config{Domain: "football.example.com", Selector: "brisbane",
		Key: ed25519.NewKeyFromSeed(seed), NoOversign: true,
		Headers: []string{"from", "to", "subject", "date", "message-id", "from", "subject", "date"},
		Now:     func() time.Time { return time.Unix(1528637909, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(readFile(t, "rfc8463-unsigned.eml"))
	if err != nil {
		t.Fatal(err)
	}
	h := strings.ReplaceAll(between(strings.ReplaceAll(string(sig), "\r\n\t", " "), " h=", ";"), " ", "")
	if h != "from:to:subject:date:message-id:from:subject:date" {
		t.Errorf("h = %q", h)
	}
	res := (&dkim.Verifier{Resolver: rfcDNS()}).Verify(context.Background(), append(sig, readFile(t, "rfc8463-unsigned.eml")...))
	if len(res) != 1 || res[0].Status != dkim.Pass {
		t.Errorf("%+v", res)
	}
}

func TestSignerRejectsWhatItCannotSign(t *testing.T) {
	key, _ := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	for name, cfg := range map[string]dkim.Config{
		"no domain":    {Selector: "s", Key: key.Signer},
		"no selector":  {Domain: "a.com", Key: key.Signer},
		"no key":       {Domain: "a.com", Selector: "s"},
		"bad selector": {Domain: "a.com", Selector: "a b", Key: key.Signer},
		"bad canon":    {Domain: "a.com", Selector: "s", Key: key.Signer, HeaderCanon: "other"},
		"no from":      {Domain: "a.com", Selector: "s", Key: key.Signer, Headers: []string{"to"}},
		"bad header":   {Domain: "a.com", Selector: "s", Key: key.Signer, Headers: []string{"from", "a:b"}},
	} {
		if _, err := dkim.NewSigner(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := dkim.GenerateRSAKey(512); err == nil {
		t.Error("a 512-bit key was generated")
	}
	signer, _ := dkim.NewSigner(dkim.Config{Domain: "a.com", Selector: "s", Key: key.Signer})
	if _, err := signer.Sign([]byte("To: a@b.c\r\n\r\nbody\r\n")); !errors.Is(err, dkim.ErrNoFrom) {
		t.Errorf("no From: %v", err)
	}
	if _, err := signer.Sign(nil); err == nil {
		t.Error("an empty message was signed")
	}
}

func TestVerifierFailures(t *testing.T) {
	rsaKey, _ := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	signer, _ := dkim.NewSigner(dkim.Config{Domain: "football.example.com", Selector: "s1", Key: rsaKey.Signer,
		Expiration: time.Hour, Now: func() time.Time { return time.Unix(1000, 0) }})
	msg := readFile(t, "rfc8463-unsigned.eml")
	signed, _ := signer.SignMessage(msg)
	at := func(sec int64) func() time.Time { return func() time.Time { return time.Unix(sec, 0) } }
	good := fakeDNS{"s1._domainkey.football.example.com": {rfcRSARecord}}

	check := func(name string, v *dkim.Verifier, in []byte, status dkim.Status, target error) {
		t.Helper()
		res := v.Verify(context.Background(), in)
		if len(res) != 1 || res[0].Status != status {
			t.Errorf("%s: %+v", name, res)
			return
		}
		if target != nil && !errors.Is(res[0].Err, target) {
			t.Errorf("%s: error %v, want %v", name, res[0].Err, target)
		}
	}
	check("valid", &dkim.Verifier{Resolver: good, Now: at(2000)}, signed, dkim.Pass, nil)
	check("expired", &dkim.Verifier{Resolver: good, Now: at(1000 + 3601)}, signed, dkim.Fail, dkim.ErrExpired)
	check("no key", &dkim.Verifier{Resolver: fakeDNS{}, Now: at(2000)}, signed, dkim.PermError, dkim.ErrNoKey)
	check("dns down", &dkim.Verifier{Resolver: brokenDNS{}, Now: at(2000)}, signed, dkim.TempError, nil)
	check("revoked", &dkim.Verifier{Resolver: fakeDNS{"s1._domainkey.football.example.com": {"v=DKIM1; k=rsa; p="}}, Now: at(2000)},
		signed, dkim.PermError, dkim.ErrKeyRevoked)
	check("wrong key", &dkim.Verifier{Resolver: fakeDNS{"s1._domainkey.football.example.com": {rfcEd25519Record}}, Now: at(2000)},
		signed, dkim.PermError, dkim.ErrBadKey)
	check("min bits", &dkim.Verifier{Resolver: good, MinRSABits: 2048, Now: at(2000)}, signed, dkim.PermError, dkim.ErrWeakKey)
	check("garbage record", &dkim.Verifier{Resolver: fakeDNS{"s1._domainkey.football.example.com": {"not a key"}}, Now: at(2000)},
		signed, dkim.PermError, dkim.ErrBadKey)

	broken := bytes.Replace(signed, []byte("v=1;"), []byte("v=2;"), 1)
	check("version", &dkim.Verifier{Resolver: good, Now: at(2000)}, broken, dkim.PermError, dkim.ErrBadSignature)
	noFrom := regexp.MustCompile(`(?s)([\t ])h=[^;]*;`).ReplaceAll(signed, []byte("${1}h=to;"))
	check("from not signed", &dkim.Verifier{Resolver: good, Now: at(2000)}, noFrom, dkim.PermError, dkim.ErrFromNotSigned)
	foreign := bytes.Replace(signed, []byte("DKIM-Signature: v=1;"), []byte("DKIM-Signature: i=a@evil.com; v=1;"), 1)
	check("identity", &dkim.Verifier{Resolver: good, Now: at(2000)}, foreign, dkim.PermError, dkim.ErrIdentity)

	if res := (&dkim.Verifier{Resolver: good}).Verify(context.Background(), msg); len(res) != 0 {
		t.Errorf("an unsigned message yields %d results", len(res))
	}
	testing_ := fakeDNS{"s1._domainkey.football.example.com": {rfcRSARecord + "; t=y"}}
	if res := (&dkim.Verifier{Resolver: testing_, Now: at(2000)}).Verify(context.Background(), signed); !res[0].Testing || res[0].Status != dkim.Pass {
		t.Errorf("testing key: %+v", res[0])
	}
}

func TestBodyLengthTag(t *testing.T) {
	rsaKey, _ := dkim.ParsePrivateKey([]byte(rfcRSAKey))
	signer, _ := dkim.NewSigner(dkim.Config{Domain: "football.example.com", Selector: "s1", Key: rsaKey.Signer})
	signed, _ := signer.SignMessage(readFile(t, "rfc8463-unsigned.eml"))
	// Hand-written signatures with l= are checked against the prefix only.
	v := &dkim.Verifier{Resolver: fakeDNS{"s1._domainkey.football.example.com": {rfcRSARecord}}}
	if res := v.Verify(context.Background(), append(signed, []byte("appended\r\n")...)); res[0].Status != dkim.Fail {
		t.Errorf("a body with appended text passed without l=: %+v", res[0])
	}
}

func TestKeyGenerationAndRecords(t *testing.T) {
	for _, alg := range []dkim.Algorithm{dkim.RSASHA256, dkim.Ed25519SHA256} {
		key, err := dkim.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		pem, err := key.PrivateKeyPEM()
		if err != nil || !bytes.HasPrefix(pem, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Fatalf("PEM: %v %q", err, pem)
		}
		back, err := dkim.ParsePrivateKey(pem)
		if err != nil || back.Algorithm != alg {
			t.Fatalf("ParsePrivateKey: %v %v", back, err)
		}
		txt, _ := key.TXT()
		rec, err := dkim.ParseKeyRecord(txt)
		if err != nil || rec.KeyType != alg.KeyType() {
			t.Fatalf("record %q: %v", txt, err)
		}
		if alg == dkim.RSASHA256 {
			if pub := rec.Public.(*rsa.PublicKey); pub.N.BitLen() != 2048 {
				t.Errorf("RSA key of %d bits", pub.N.BitLen())
			}
			if len(txt) <= 255 {
				t.Error("an RSA 2048 record fits in one string, so SplitTXT is untested")
			}
		}
		parts := dkim.SplitTXT(txt)
		if strings.Join(parts, "") != txt {
			t.Error("SplitTXT lost bytes")
		}
		for _, p := range parts {
			if len(p) > 255 {
				t.Errorf("part of %d bytes", len(p))
			}
		}
		signed := signAndVerify(t, key, dkim.Relaxed, dkim.Relaxed, nil)
		if signed[0].Status != dkim.Pass {
			t.Errorf("%s: %+v", alg, signed[0])
		}
	}
	if got := dkim.RecordName("s1", "example.com."); got != "s1._domainkey.example.com" {
		t.Errorf("RecordName = %q", got)
	}
	if _, err := dkim.GenerateKey("nope"); err == nil {
		t.Error("an unknown algorithm was accepted")
	}
	if _, err := dkim.ParsePrivateKey([]byte("not pem")); err == nil {
		t.Error("garbage parsed")
	}
}

func TestParseKeyRecord(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
		revoked bool
	}{
		{rfcRSARecord, false, false},
		{rfcEd25519Record, false, false},
		{strings.TrimPrefix(rfcRSARecord, "v=DKIM1; k=rsa; "), false, false}, // v and k are optional
		{"v=DKIM1; p=", true, true},
		{"v=DKIM2; p=abc", true, false},
		{"k=rsa", true, false},
		{"v=DKIM1; k=rsa; p=%%%", true, false},
		{"v=DKIM1; k=dsa; p=AAAA", true, false},
		{"v=DKIM1; h=sha1; " + strings.TrimPrefix(rfcRSARecord, "v=DKIM1; "), true, false},
		{"v=DKIM1; s=other; " + strings.TrimPrefix(rfcRSARecord, "v=DKIM1; "), true, false},
		{"v=DKIM1; k=ed25519; p=AAAA", true, false},
		{"a=1; a=2", true, false},
		{"", true, false},
	}
	for _, c := range cases {
		_, err := dkim.ParseKeyRecord(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: %v", c.in, err)
		}
		if c.revoked && !errors.Is(err, dkim.ErrKeyRevoked) {
			t.Errorf("%q: %v is not a revocation", c.in, err)
		}
	}
}

func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}
