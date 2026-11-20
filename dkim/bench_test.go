package dkim_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/hyz-is/arandu-mail/dkim"
)

// message50KB is a message of about 50 KB with the headers of a transactional
// e-mail.
func message50KB() []byte {
	var sb strings.Builder
	sb.WriteString("From: Acme <hello@acme.com>\r\nTo: ana@example.com\r\nSubject: Your invoice\r\n" +
		"Date: Fri, 20 Nov 2026 10:30:00 -0300\r\nMessage-ID: <bench@acme.com>\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	line := "<p>Ol=C3=A1, este =C3=A9 um par=C3=A1grafo de exemplo com acentua=C3=A7=C3=A3o e <b>negrito</b>.</p> \r\n"
	for sb.Len() < 50<<10 {
		sb.WriteString(line)
	}
	return []byte(sb.String())
}

func benchSigner(b *testing.B, alg dkim.Algorithm, hc, bc dkim.Canon) *dkim.Signer {
	key, err := dkim.GenerateKey(alg)
	if err != nil {
		b.Fatal(err)
	}
	s, err := dkim.NewSigner(dkim.Config{Domain: "acme.com", Selector: "s1", Key: key.Signer, HeaderCanon: hc, BodyCanon: bc})
	if err != nil {
		b.Fatal(err)
	}
	return s
}

func benchSign(b *testing.B, s *dkim.Signer) {
	msg := message50KB()
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		buf, err = s.AppendSignature(buf[:0], msg)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSignEd25519Relaxed50KB signs a 50 KB message with Ed25519.
func BenchmarkSignEd25519Relaxed50KB(b *testing.B) {
	benchSign(b, benchSigner(b, dkim.Ed25519SHA256, dkim.Relaxed, dkim.Relaxed))
}

// BenchmarkSignRSA2048Relaxed50KB signs a 50 KB message with RSA-2048.
func BenchmarkSignRSA2048Relaxed50KB(b *testing.B) {
	benchSign(b, benchSigner(b, dkim.RSASHA256, dkim.Relaxed, dkim.Relaxed))
}

// BenchmarkSignEd25519Simple50KB uses simple canonicalization.
func BenchmarkSignEd25519Simple50KB(b *testing.B) {
	benchSign(b, benchSigner(b, dkim.Ed25519SHA256, dkim.Simple, dkim.Simple))
}

// BenchmarkSignEd25519Parallel signs on every core, the way a delivery worker
// pool does.
func BenchmarkSignEd25519Parallel(b *testing.B) {
	s := benchSigner(b, dkim.Ed25519SHA256, dkim.Relaxed, dkim.Relaxed)
	msg := message50KB()
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 0, 2048)
		for pb.Next() {
			var err error
			buf, err = s.AppendSignature(buf[:0], msg)
			if err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkVerifyEd25519Relaxed50KB verifies a signed 50 KB message.
func BenchmarkVerifyEd25519Relaxed50KB(b *testing.B) {
	seed, _ := base64.StdEncoding.DecodeString(rfcEd25519Seed)
	key, _ := dkim.KeyPairFrom(ed25519.NewKeyFromSeed(seed))
	s, err := dkim.NewSigner(dkim.Config{Domain: "football.example.com", Selector: "brisbane", Key: key.Signer})
	if err != nil {
		b.Fatal(err)
	}
	signed, err := s.SignMessage(message50KB())
	if err != nil {
		b.Fatal(err)
	}
	v := &dkim.Verifier{Resolver: rfcDNS()}
	ctx := context.Background()
	b.ReportAllocs()
	b.SetBytes(int64(len(signed)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := v.Verify(ctx, signed); len(r) != 1 || r[0].Status != dkim.Pass {
			b.Fatalf("%+v", r)
		}
	}
}
