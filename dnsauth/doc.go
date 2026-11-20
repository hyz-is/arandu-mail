// Package dnsauth builds and checks the DNS side of sending mail for a domain:
// the records a customer publishes, and the standards a receiver applies to
// them.
//
// Records returns the records the domain must publish, in the layout of the
// useSend dashboard: the DKIM key at selector._domainkey, the SPF record and
// the MX at the mail-from subdomain, and a recommended DMARC record. Verify
// looks each one up and gives it a Status (NOT_STARTED, PENDING, SUCCESS,
// FAILED or TEMPORARY_FAILURE), the enum DomainStatus of useSend.
//
// The receiver's side is here too, because a sender needs it to test itself:
// SPFChecker.Check evaluates check_host of RFC 7208 in full (include, a, mx, ptr, ip4,
// ip6, exists, redirect, exp, macros, and the limits of 10 DNS-querying terms
// and 2 void lookups); ParseDMARC, LookupDMARC and EvaluateDMARC read a policy
// and decide alignment with the public suffix list (RFC 7489); the MTA-STS
// functions read the TXT record and fetch the policy (RFC 8461); and the
// TLS-RPT functions read the reporting record (RFC 8460).
//
// Every lookup goes through the Resolver interface. A *net.Resolver satisfies
// it, and Fake is an in-memory one for tests. The policy fetch goes through
// HTTPClient, which a *http.Client satisfies.
//
// The package depends on the standard library and on golang.org/x/net for the
// public suffix list.
package dnsauth
