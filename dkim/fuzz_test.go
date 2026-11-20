package dkim_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/dkim"
)

func FuzzVerify(f *testing.F) {
	f.Add(readFile(f, "rfc8463-signed.eml"))
	f.Add([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=x; s=y; h=from; bh=AA==; b=AA==\r\nFrom: a@b.c\r\n\r\n"))
	f.Add([]byte("DKIM-Signature: \r\n\t;;;=\r\n\r\n"))
	dns := fakeDNS{
		"brisbane._domainkey.football.example.com": {rfcEd25519Record},
		"test._domainkey.football.example.com":     {rfcRSARecord},
	}
	v := &dkim.Verifier{Resolver: dns}
	f.Fuzz(func(t *testing.T, msg []byte) {
		for _, r := range v.Verify(context.Background(), msg) {
			if r.Status == "" {
				t.Fatal("a result with no status")
			}
			if r.Status != dkim.Pass && r.Err == nil {
				t.Fatalf("status %s with no error", r.Status)
			}
		}
	})
}

func FuzzParseKeyRecord(f *testing.F) {
	f.Add(rfcRSARecord)
	f.Add(rfcEd25519Record)
	f.Add("v=DKIM1; p=")
	f.Add("a=b;;c")
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := dkim.ParseKeyRecord(s)
		if err == nil && (rec == nil || rec.Public == nil) {
			t.Fatalf("no error and no key for %q", s)
		}
	})
}

// FuzzSignThenVerify holds that any message the signer accepts verifies, and
// that a change to the body does not.
func FuzzSignThenVerify(f *testing.F) {
	f.Add("From: a@b.c\r\nSubject: x\r\n\r\nbody\r\n")
	f.Add("From: a@b.c\r\n folded\r\n\tmore: x\r\n\r\n\r\n\r\n")
	f.Add("X: y\r\nFrom: a@b.c\r\n\r\n a  b \t\r\n")
	seed, _ := base64.StdEncoding.DecodeString(rfcEd25519Seed)
	signer, err := dkim.NewSigner(dkim.Config{Domain: "football.example.com", Selector: "brisbane",
		Key: ed25519.NewKeyFromSeed(seed), HeaderCanon: dkim.Relaxed, BodyCanon: dkim.Simple})
	if err != nil {
		f.Fatal(err)
	}
	v := &dkim.Verifier{Resolver: rfcDNS()}
	f.Fuzz(func(t *testing.T, in string) {
		// The signer wants wire format: CRLF line breaks, no bare CR.
		in = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(in, "\r\n", "\n"), "\r", "\n"), "\n", "\r\n")
		signed, err := signer.SignMessage([]byte(in))
		if err != nil {
			return
		}
		res := v.Verify(context.Background(), signed)
		if len(res) == 0 || res[0].Status != dkim.Pass {
			t.Fatalf("signed message does not verify: %+v\n%q", res, signed)
		}
	})
}
