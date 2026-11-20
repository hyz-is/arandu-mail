package verp_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/verp"
)

func codec(t testing.TB, keys ...string) *verp.Codec {
	t.Helper()
	var ks [][]byte
	for _, k := range keys {
		ks = append(ks, []byte(k))
	}
	c, err := verp.New("bounces", ks...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncodeDecode(t *testing.T) {
	c := codec(t, "secret")
	addr, err := c.Encode("cm3x8k2p0000108l5abcd", "Mail.Acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(addr, "bounces+cm3x8k2p0000108l5abcd.") || !strings.HasSuffix(addr, "@mail.acme.com") {
		t.Errorf("address = %q", addr)
	}
	if strings.ToLower(addr) != addr {
		t.Errorf("address is not lowercase: %q", addr)
	}
	id, domain, err := c.Decode(addr)
	if err != nil || id != "cm3x8k2p0000108l5abcd" || domain != "mail.acme.com" {
		t.Errorf("Decode = %q %q %v", id, domain, err)
	}
	// The mail system may change the case of the local part, and a Return-Path
	// header wraps the address in angle brackets.
	for _, in := range []string{strings.ToUpper(addr), "<" + addr + ">", "  " + addr + " "} {
		if id, _, err := c.Decode(in); err != nil || id != "cm3x8k2p0000108l5abcd" {
			t.Errorf("Decode(%q) = %q, %v", in, id, err)
		}
	}
	other, _ := c.Encode("cm3x8k2p0000108l5abcd", "mail.acme.com")
	if other != addr {
		t.Error("the address is not deterministic")
	}
}

func TestInternationalDomain(t *testing.T) {
	c := codec(t, "k")
	addr, err := c.Encode("id1", "bücher.example")
	if err != nil || !strings.HasSuffix(addr, "@xn--bcher-kva.example") {
		t.Fatalf("%q, %v", addr, err)
	}
	if _, d, err := c.Decode(addr); err != nil || d != "xn--bcher-kva.example" {
		t.Errorf("%q %v", d, err)
	}
}

func TestForgeriesAreRefused(t *testing.T) {
	c := codec(t, "secret")
	addr, _ := c.Encode("msg-1", "mail.acme.com")
	local, domain, _ := strings.Cut(addr, "@")
	cases := map[string]string{
		"another id":     strings.Replace(local, "msg-1", "msg-2", 1) + "@" + domain,
		"another domain": local + "@mail.evil.com",
		"truncated tag":  local[:len(local)-1] + "@" + domain,
		"changed tag":    local[:len(local)-1] + "a@" + domain,
		"another key":    func() string { a, _ := codec(t, "other").Encode("msg-1", "mail.acme.com"); return a }(),
	}
	for name, in := range cases {
		if _, _, err := c.Decode(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, _, err := c.Decode(strings.Replace(local, "msg-1", "msg-2", 1) + "@" + domain); !errors.Is(err, verp.ErrBadTag) {
		t.Errorf("a changed id gives %v, want ErrBadTag", err)
	}
	for _, in := range []string{"", "@", "a@b", "other+id.tag@x.com", "bounces@x.com", "bounces+id@x.com",
		"bounces+.abcdefghijklm@x.com", "bounces+id.@x.com", "bounces+ID!.abcdefghijklm@x.com", "no-at-sign"} {
		if _, _, err := c.Decode(in); !errors.Is(err, verp.ErrNotVERP) {
			t.Errorf("Decode(%q) = %v, want ErrNotVERP", in, err)
		}
	}
}

func TestKeyRotation(t *testing.T) {
	old := codec(t, "old")
	addr, _ := old.Encode("m1", "mail.acme.com")
	rotated := codec(t, "new", "old")
	if _, _, err := rotated.Decode(addr); err != nil {
		t.Errorf("an address made with the old key is refused after rotation: %v", err)
	}
	fresh, _ := rotated.Encode("m1", "mail.acme.com")
	if fresh == addr {
		t.Error("the new key was not used to sign")
	}
	if _, _, err := old.Decode(fresh); err == nil {
		t.Error("the old codec accepted an address of the new key")
	}
}

func TestInvalidInput(t *testing.T) {
	c := codec(t, "k")
	for _, id := range []string{"", "Upper", "has.dot", "has space", "a@b", strings.Repeat("a", 101), "é"} {
		if _, err := c.Encode(id, "a.com"); !errors.Is(err, verp.ErrInvalidID) {
			t.Errorf("Encode(%q) = %v", id, err)
		}
	}
	if _, err := c.Encode("ok", ""); err == nil {
		t.Error("empty domain accepted")
	}
	if _, err := verp.New("bounces"); !errors.Is(err, verp.ErrNoKey) {
		t.Error("no key accepted")
	}
	if _, err := verp.New("bounces", nil); !errors.Is(err, verp.ErrNoKey) {
		t.Error("empty key accepted")
	}
	if _, err := verp.New("Bad Prefix", []byte("k")); err == nil {
		t.Error("bad prefix accepted")
	}
}

func FuzzDecode(f *testing.F) {
	c := codec(f, "secret")
	good, _ := c.Encode("msg-1", "mail.acme.com")
	for _, s := range []string{good, strings.ToUpper(good), "<" + good + ">", "bounces+a.b@c", "", "@@@", "a+b.c@d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, domain, err := c.Decode(s)
		if err != nil {
			return
		}
		// Whatever decodes was made by Encode: it must encode back to itself.
		again, err := c.Encode(id, domain)
		if err != nil {
			t.Fatalf("Decode(%q) = %q %q, which Encode refuses: %v", s, id, domain, err)
		}
		if got := strings.ToLower(strings.Trim(strings.TrimSpace(s), "<>")); got != again {
			t.Fatalf("Decode(%q) accepted a different address than Encode makes: %q", s, again)
		}
	})
}

func BenchmarkEncode(b *testing.B) {
	c := codec(b, "secret")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := c.Encode("cm3x8k2p0000108l5abcd", "mail.acme.com"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	c := codec(b, "secret")
	addr, _ := c.Encode("cm3x8k2p0000108l5abcd", "mail.acme.com")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := c.Decode(addr); err != nil {
			b.Fatal(err)
		}
	}
}
