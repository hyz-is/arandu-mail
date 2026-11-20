<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Mail

Pure Go libraries for the protocols a mail platform speaks: build and read
messages, sign and verify DKIM, read bounces and feedback reports, write bounce
addresses that name the message, and publish and check the DNS records a sending
domain needs.

It is a set of libraries. It registers no route, owns no table and decides no
authorization, so there is nothing to wire in `bootstrap/app.go`, nothing to
construct for the package as a whole, and no `aru migrate` to run. An
application imports the package it needs and calls it.

## Install

```bash
go get github.com/hyz-is/arandu-mail
```

The module requires `golang.org/x/net` (for the public suffix list) and nothing
else. `arandu.mod.toml` declares the network capability, because `dnsauth` asks
resolvers for records and fetches an MTA-STS policy; it declares no filesystem,
no process and no migration.

| package | what it does | standards |
| --- | --- | --- |
| `arandu-mail/mime` | build and parse messages | RFC 5322, 2045 to 2049, 2047, 2231, 6532, 2369, 8058 |
| `arandu-mail/dkim` | keys, signer, verifier | RFC 6376, 8463, 8301 |
| `arandu-mail/dsn` | read bounces, classify them in the SES vocabulary | RFC 3464, 3463 |
| `arandu-mail/arf` | read feedback-loop complaints | RFC 5965 |
| `arandu-mail/verp` | `bounces+<id>.<tag>@domain` addresses with an HMAC tag | VERP |
| `arandu-mail/dnsauth` | DNS records to publish and verify, SPF, DMARC, MTA-STS, TLS-RPT | RFC 7208, 7489, 8461, 8460 |

## Build a message

```go
import "github.com/hyz-is/arandu-mail/mime"

b := mime.NewBuilder().
	From("Acme <hello@acme.com>").
	To("José da Silva <jose@exemplo.com.br>").
	Subject("Sua fatura está pronta").
	Text("Olá José, sua fatura está pronta.").
	HTML(`<p>Olá José, <img src="cid:logo"></p>`).
	Attach(mime.Attachment{Filename: "logo.png", ContentID: "logo", Content: logo}).
	Attach(mime.Attachment{Filename: "fatura.pdf", Content: pdf}).
	Header("X-Entity-Ref-ID", "invoice-42").
	ListUnsubscribe("https://acme.com/unsubscribe/42").
	OneClickUnsubscribe()

raw, err := b.Build()             // []byte, CRLF, ready for DKIM and SMTP DATA
rcpt, err := b.Recipients()       // the envelope: To, Cc and Bcc
id := b.ID()                      // the Message-ID, generated once and kept
```

The structure follows the content: `text/plain` alone, `text/html` alone,
`multipart/alternative` for both, `multipart/related` when an image is inline
(an attachment with a `ContentID`), and `multipart/mixed` around the files. Each
text part is 7bit when it is plain ASCII with short lines, quoted-printable when
most of it is ASCII, and base64 when most of it is not. Subjects, display names
and custom headers that are not ASCII travel as RFC 2047 encoded words, file
names as RFC 2231 parameters, and a non-ASCII domain as Punycode. A local part
that is not ASCII needs `SMTPUTF8(true)`, and `NeedsSMTPUTF8()` tells the sender
to ask for the extension.

A CR, LF or NUL in a subject, an address, a custom header, a file name, a
content id or a URL is an error (`ErrHeaderInjection`), never a second header.
Custom headers cannot take the place of the ones the builder writes.

`AppendTo(dst)` and `WriteTo(w)` build into a buffer the caller or a pool owns.

## Read a message

```go
m, err := mime.ParseBytes(raw, nil) // or mime.Parse(r, &mime.Options{MaxSize: 25 << 20})

m.From, m.To, m.Cc, m.Bcc, m.ReplyTo  // []mime.Address, groups flattened
m.Subject, m.Text, m.HTML             // decoded to UTF-8, LF line breaks
m.Attachments                         // Filename, ContentType, Content, ContentID, Inline
m.Header.Get("X-Entity-Ref-ID")       // every field, in order
```

The parser reads what real mail looks like: bare LF line ends, folded headers,
encoded words, RFC 2231 file names, quoted-printable and base64 with stray
bytes, a missing closing boundary, and the charsets UTF-8, US-ASCII, ISO-8859-1,
ISO-8859-15 and Windows-1252 (a label for another charset goes to
`Options.CharsetDecoder`, or is read as UTF-8 with a warning). Nesting depth,
part count and size are bounded. `mime.ParseEntity` gives the whole MIME tree,
which `dsn` and `arf` use to find their parts.

This is what an SMTP relay needs to turn the `DATA` of a submission into the
JSON body of `POST /api/v1/emails`: `m.From`, `m.To`, `m.Cc`, `m.Subject`,
`m.Text`, `m.HTML`, `m.ReplyTo` and `m.Attachments`. `mime.ResolveRecipients(m,
envelope)` takes the envelope recipients that are not in `To` or `Cc` as Bcc, and
`mime.ForwardableHeaders(m.Header)` returns the end-to-end headers worth passing
on (not the ones the builder rewrites, the trace fields or the signatures).

## Sign and verify DKIM

```go
import "github.com/hyz-is/arandu-mail/dkim"

key, err := dkim.GenerateKey(dkim.RSASHA256)  // 2048 bits; or dkim.Ed25519SHA256
pem, err := key.PrivateKeyPEM()               // store it sealed
txt, err := key.TXT()                         // "v=DKIM1; k=rsa; p=..." for selector._domainkey.domain

signer, err := dkim.NewSigner(dkim.Config{Domain: "acme.com", Selector: "meeng", Key: key.Signer})
signed, err := signer.SignMessage(raw)        // the DKIM-Signature field, then the message
```

Relaxed/relaxed by default, simple and relaxed both supported. The signed
fields are the ones RFC 6376 section 5.4.1 recommends, and From, To and Subject
are oversigned, so a field added in transit breaks the signature. A `Signer` is
safe for concurrent use.

```go
v := &dkim.Verifier{Resolver: net.DefaultResolver}
for _, r := range v.Verify(ctx, signed) {
	fmt.Println(r.Domain, r.Selector, r.Status) // pass, fail, temperror, permerror
}
```

The verifier checks `bh=`, `b=`, `x=`, `l=`, the identity, the key record
(`v`, `k`, `h`, `s`, `t`, revoked keys), and refuses RSA keys under 1024 bits.
The tests verify the two signatures of the RFC 8463 appendix, the RSA and the
Ed25519 one, and the canonicalization examples of RFC 6376 section 3.4.5.

## Read bounces and complaints

```go
import "github.com/hyz-is/arandu-mail/dsn"

rep, err := dsn.Parse(raw, nil)
for _, r := range rep.Recipients {
	c := r.Classification()           // c.Type: Permanent|Transient|Undetermined
	_ = c.SubType                     // General|NoEmail|Suppressed|MailboxFull|MessageTooLarge|ContentRejected|AttachmentRejected
	_ = r.FinalRecipient              // the address that bounced
}
rep.OriginalEnvelopeID                // Original-Envelope-Id
rep.OriginalHeader("X-Meeng-Email-ID") // a header of the returned original

dsn.Classify(550, "5.1.1", "User unknown") // Permanent / NoEmail
```

`Parse` reads a standard RFC 3464 report and falls back to heuristics for the
bounces that are not one (`rep.Heuristic` says so): the layouts of Postfix,
Exim, Gmail and Microsoft, the `X-Failed-Recipients` header, and a free-text
notice with a recipient and a status code in it. `Classify` uses the
vocabulary of SES and of the useSend API: a full mailbox and an oversize message
are Transient, a refused attachment or content is Transient, and an address that
does not exist is Permanent/NoEmail.

```go
import "github.com/hyz-is/arandu-mail/arf"

rep, err := arf.Parse(raw, nil)       // rep.FeedbackType, rep.OriginalRcptTo, rep.OriginalMessageID
rep.EmailID                           // the X-Meeng-Email-ID of the original, when returned
rep.IsComplaint()                     // abuse, fraud or virus
```

## Bounce addresses

```go
import "github.com/hyz-is/arandu-mail/verp"

codec, err := verp.New("bounces", currentKey, previousKey) // the first key signs, all verify
addr, err := codec.Encode("cm3x8k2p0000108l5", "mail.acme.com")
// bounces+cm3x8k2p0000108l5.fijr3mu2iy3km@mail.acme.com
id, domain, err := codec.Decode(rcptTo) // ErrNotVERP, or ErrBadTag for a forgery
```

The tag is 64 bits of an HMAC-SHA-256 over the domain and the id, written in
lowercase base32. Ids hold `a-z`, `0-9`, `-` and `_`.

## DNS records, SPF, DMARC, MTA-STS

```go
import "github.com/hyz-is/arandu-mail/dnsauth"

records, err := dnsauth.Records(dnsauth.Config{
	Domain: "acme.com", DKIMSelector: "meeng", DKIMPublicKey: pub,
	InboundHost: "inbound.meeng.dev", SPFMechanisms: []string{"include:spf.meeng.dev"},
})
// MX  mail              10  inbound.meeng.dev
// TXT meeng._domainkey      p=MIIBIj...
// TXT mail                  v=spf1 include:spf.meeng.dev ~all
// TXT _dmarc                v=DMARC1; p=none;          (recommended)

checked := dnsauth.Verify(ctx, dnsauth.DefaultResolver(), records, dnsauth.VerifyOptions{})
status := dnsauth.Overall(checked) // NOT_STARTED, PENDING, SUCCESS, FAILED, TEMPORARY_FAILURE
```

The records have the columns of the useSend dashboard (type, name relative to
the zone, value, TTL, priority, status), and a subdomain such as
`send.acme.com` gives `mail.send` and `meeng._domainkey.send`, with DMARC at the
zone. `Fake` is an in-memory resolver for tests.

```go
checker := &dnsauth.SPFChecker{Resolver: dnsauth.DefaultResolver()}
v := checker.Check(ctx, ip, "acme.com", "bounce@acme.com", "mx.acme.com") // v.Result: pass, fail, softfail...

res, err := dnsauth.EvaluateDMARC(ctx, resolver, dnsauth.DMARCInput{FromDomain: "acme.com", SPF: ..., DKIM: ...})

mta, err := dnsauth.LookupMTASTS(ctx, resolver, dnsauth.NewHTTPClient(0), "example.com")
mta.Policy.MatchMX("mx1.example.com")
```

`SPFChecker.Check` is the full `check_host` of RFC 7208: `include`, `a`, `mx`, `ptr`,
`ip4`, `ip6`, `exists`, `redirect`, `exp`, macros, the limit of 10
DNS-querying terms and the limit of 2 void lookups. DMARC alignment uses the
public suffix list. MTA-STS fetches the policy over HTTPS without following
redirects and caps it at 64 KiB; TLS-RPT reads the reporting record.

## Performance

Measured with `go test -bench . -benchmem` on an Apple M4 Max (14 cores),
Go 1.26.6, a 50 KB message of HTML and text with accents.

| benchmark | time | throughput | allocations |
| --- | --- | --- | --- |
| `mime` build, 50 KB, quoted-printable | 88 µs | 680 MB/s | 4 (256 B) |
| `mime` build, small transactional message | 0.58 µs | 955 MB/s | 3 (240 B) |
| `mime` build, 100 KB attachment | 39 µs | 3.6 GB/s | 4 |
| `mime` parse, 50 KB | 99 µs | 601 MB/s | 141 |
| `mime` parse, MIME tree only | 67 µs | 886 MB/s | 40 |
| `dkim` sign, Ed25519, relaxed, 50 KB | 85 µs | 604 MB/s | 20 |
| `dkim` sign, Ed25519, simple, 50 KB | 38 µs | 1.36 GB/s | 20 |
| `dkim` sign, RSA-2048, relaxed, 50 KB | 781 µs | 66 MB/s | 21 |
| `dkim` sign, Ed25519, 14 cores in parallel | 9.1 µs per message | 5.6 GB/s | 20 |
| `dkim` verify, Ed25519, relaxed, 50 KB | 102 µs | 507 MB/s | 28 |
| `dsn` parse a standard report | 5.5 µs | 318 MB/s | 145 |
| `dsn` parse a free-text bounce | 7.1 µs | 110 MB/s | 50 |
| `dsn.Classify` | 0.64 µs | | 2 |
| `arf` parse a report | 5.9 µs | 257 MB/s | 151 |
| `verp` encode / decode | 0.41 µs / 0.40 µs | | 13 / 12 |
| `dnsauth` check SPF with one include (fake resolver) | 1.0 µs | | 29 |

The build and the signature stream through pooled buffers and a pooled SHA-256
state, so the allocation count does not grow with the size of the message. The
RSA signature is the private-key operation itself; an Ed25519 key signs ten
times faster.

## Tests

Every parser has a fuzz test: `mime` (message, addresses, encoded words, media
types, the builder), `dkim` (verifier, key records, sign then verify), `dsn`,
`arf`, `verp` and `dnsauth` (SPF parse and evaluation, DMARC, MTA-STS, TLS-RPT).
The inputs that found a defect are kept in `testdata/fuzz` and run on every
`go test`. The builder is checked against the standard library (`net/mail`,
`mime/multipart`, `mime/quotedprintable`) as an oracle.

```bash
GOWORK=off go test -race ./...
GOWORK=off go test ./mime -run='^$' -fuzz='^FuzzParse$' -fuzztime=30s
GOWORK=off go test ./... -run='^$' -bench . -benchmem
```

## License

MIT. See `LICENSE.md`.
