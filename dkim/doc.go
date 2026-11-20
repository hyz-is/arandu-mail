// Package dkim signs and verifies messages with DomainKeys Identified Mail
// (RFC 6376) using RSA-SHA256 and Ed25519-SHA256 (RFC 8463).
//
// A Signer is built once for a domain and a selector and signs any number of
// messages: canonicalization (simple or relaxed, for the headers and for the
// body) streams through a pooled SHA-256 state, so signing a message costs one
// pass over its bytes and a few allocations. The default header list is the
// recommended one of RFC 6376 section 5.4.1 with From, To and Subject
// oversigned, so a header added in transit breaks the signature.
//
// A Verifier checks every DKIM-Signature of a message. It asks a Resolver for
// the key record; a *net.Resolver satisfies it, and so does any fake a test
// needs.
//
// KeyPair generates keys and writes the TXT record to publish.
//
// Messages must use CRLF line endings, as they do on the wire. The package
// depends on the standard library and on nothing else.
package dkim
