package dnsauth_test

import (
	"context"
	"fmt"
	"net"

	"github.com/hyz-is/arandu-mail/dnsauth"
)

func ExampleRecords() {
	records, err := dnsauth.Records(dnsauth.Config{
		Domain:        "acme.com",
		DKIMSelector:  "meeng",
		DKIMPublicKey: "MIIBIjANBgkq...",
		InboundHost:   "inbound.meeng.dev",
		SPFMechanisms: []string{"include:spf.meeng.dev"},
	})
	if err != nil {
		panic(err)
	}
	for _, r := range records {
		fmt.Printf("%-4s %-18s %-8s %s\n", r.Type, r.Name, r.Priority, r.Value)
	}

	// Output:
	// MX   mail               10       inbound.meeng.dev
	// TXT  meeng._domainkey            p=MIIBIjANBgkq...
	// TXT  mail                        v=spf1 include:spf.meeng.dev ~all
	// TXT  _dmarc                      v=DMARC1; p=none;
}

func ExampleSPFChecker() {
	dns := dnsauth.NewFake().
		SetTXT("acme.com", "v=spf1 ip4:192.0.2.0/24 include:spf.meeng.dev -all").
		SetTXT("spf.meeng.dev", "v=spf1 ip4:203.0.113.0/24 -all")

	checker := &dnsauth.SPFChecker{Resolver: dns}
	for _, ip := range []string{"203.0.113.9", "198.51.100.1"} {
		v := checker.Check(context.Background(), net.ParseIP(ip), "acme.com", "bounce@acme.com", "mx.acme.com")
		fmt.Println(ip, v.Result, v.Mechanism)
	}

	// Output:
	// 203.0.113.9 pass include:spf.meeng.dev
	// 198.51.100.1 fail all
}
