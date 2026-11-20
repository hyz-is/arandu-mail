package dkim_test

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/hyz-is/arandu-mail/dkim"
)

type staticDNS map[string][]string

func (s staticDNS) LookupTXT(_ context.Context, name string) ([]string, error) { return s[name], nil }

func Example() {
	seed := make([]byte, ed25519.SeedSize) // a fixed key keeps the example repeatable
	key, err := dkim.KeyPairFrom(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		panic(err)
	}
	record, _ := key.TXT() // publish this at s1._domainkey.acme.com

	signer, err := dkim.NewSigner(dkim.Config{Domain: "acme.com", Selector: "s1", Key: key.Signer})
	if err != nil {
		panic(err)
	}
	msg := []byte("From: hello@acme.com\r\nTo: ana@example.com\r\nSubject: Hi\r\n\r\nHello\r\n")
	signed, err := signer.SignMessage(msg)
	if err != nil {
		panic(err)
	}

	v := &dkim.Verifier{Resolver: staticDNS{"s1._domainkey.acme.com": {record}}}
	for _, r := range v.Verify(context.Background(), signed) {
		fmt.Println(r.Domain, r.Selector, r.Algorithm, r.Status)
	}

	// Output:
	// acme.com s1 ed25519-sha256 pass
}
