// Package mail is the root of Arandu Mail, a set of pure Go libraries for the
// protocols a mail platform speaks. It holds no code of its own: import the
// package you need.
//
//	github.com/hyz-is/arandu-mail/mime     build and parse messages (RFC 5322, MIME)
//	github.com/hyz-is/arandu-mail/dkim     sign and verify DKIM (RFC 6376, RFC 8463)
//	github.com/hyz-is/arandu-mail/dsn      read bounces (RFC 3464) and classify them
//	github.com/hyz-is/arandu-mail/arf      read feedback reports (RFC 5965)
//	github.com/hyz-is/arandu-mail/verp     bounce addresses that name the message
//	github.com/hyz-is/arandu-mail/dnsauth  DNS records, SPF, DMARC, MTA-STS, TLS-RPT
package mail
