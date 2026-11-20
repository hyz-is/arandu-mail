---
name: mail-package
description: Use the Arandu Mail libraries (Go, Arandu) in an application instead of writing a MIME, DKIM, bounce, SPF or DMARC parser of its own. Use when the request is to "build an e-mail", "send MIME", "parse an incoming message", "sign with DKIM", "generate a DKIM key", "read a bounce", "classify a bounce", "read a feedback loop report", "write a VERP return path", "which DNS records does the customer publish", "check SPF", "verify the domain", "check MTA-STS", "go get github.com/hyz-is/arandu-mail", or when a project's go.mod already requires github.com/hyz-is/arandu-mail. Covers which package owns which job, the calls that matter, and the mistakes that put a header injection, a wrong bounce class or a missing record in an application.
license: MIT
metadata:
  audience: app
---

# Using Arandu Mail

Pure Go libraries. There is nothing to register in `bootstrap/app.go`, no
`aru migrate` and no service to construct for the package as a whole: import the
package and call it. If the application is about to write its own parser for one
of the jobs below, stop and use this one.

```bash
go get github.com/hyz-is/arandu-mail
```

## Which package owns the job

| the job | the package and the call |
| --- | --- |
| make the bytes of an e-mail | `mime.NewBuilder()`, then `.Build()` |
| read the bytes of an e-mail | `mime.ParseBytes(raw, nil)` |
| sign a message | `dkim.NewSigner(...)`, then `.SignMessage(raw)` |
| make a DKIM key and its DNS value | `dkim.GenerateKey(dkim.RSASHA256)`, `.TXT()` |
| turn a bounce into a recipient and a reason | `dsn.Parse(raw, nil)`, `dsn.Classify(...)` |
| turn a spam complaint into a message id | `arf.Parse(raw, nil)` |
| the return path of one message | `verp.New(prefix, keys...)`, `.Encode(id, domain)`, `.Decode(addr)` |
| the DNS records a customer publishes, and their status | `dnsauth.Records(cfg)`, `dnsauth.Verify(...)` |
| SPF, DMARC, MTA-STS | `dnsauth.SPFChecker`, `dnsauth.EvaluateDMARC`, `dnsauth.LookupMTASTS` |

## Build a message

```go
b := mime.NewBuilder().
	From("Acme <hello@acme.com>").To("ana@example.com").
	Subject(subject).Text(text).HTML(html).
	Header("X-Entity-Ref-ID", ref).
	ListUnsubscribe(unsubscribeURL).OneClickUnsubscribe()
raw, err := b.Build()
rcpt, err := b.Recipients() // To, Cc and Bcc: the SMTP envelope. Bcc is never in the headers
```

- Give the setters what the user wrote. Do not strip, escape or encode it first:
  the builder encodes non-ASCII subjects and names, folds lines, writes CRLF and
  refuses a CR, LF or NUL. An error from `Build` for a value that holds a line
  break is the protection working; return it as a 400, do not clean the value to
  make it pass.
- An attachment with a `ContentID` is an inline image of the HTML; refer to it
  as `cid:<ContentID>`. One without is a file.
- A message with a non-ASCII local part needs `SMTPUTF8(true)` and an SMTP
  session that offers the extension (`NeedsSMTPUTF8()`).
- Message-ID: call `b.ID()` after building if the application needs it; do not
  generate a second one.
- `OneClickUnsubscribe` needs an https URL and a DKIM signature that covers
  `List-Unsubscribe` and `List-Unsubscribe-Post`; the default signer does.

## Sign

```go
signer, err := dkim.NewSigner(dkim.Config{Domain: domain, Selector: selector, Key: key.Signer})
signed, err := signer.SignMessage(raw) // raw must have CRLF line ends, which Build gives
```

Build one `Signer` per domain and selector and keep it: it is safe for
concurrent use. The private key is sealed at rest (`key.PrivateKeyPEM()` is the
form to seal and `dkim.ParsePrivateKey` reads it back). Publish `key.TXT()` at
`dkim.RecordName(selector, domain)`; `dkim.SplitTXT` cuts it for a DNS provider
that wants strings of at most 255 bytes.

## Bounces

```go
rep, err := dsn.Parse(raw, nil)       // dsn.ErrNotDSN when it is ordinary mail
for _, r := range rep.Recipients {
	c := r.Classification()           // c.Type, c.SubType
}
```

- Suppress an address on `c.Type == dsn.Permanent`, not on every failure.
  `Transient/MailboxFull`, `MessageTooLarge`, `ContentRejected` and
  `AttachmentRejected` are about the message or the moment, not about the
  address.
- `rep.Heuristic` is true for a bounce that was not a standard report: trust
  its recipient less, and log it.
- Find the message with the bounce address (`verp.Decode` on the RCPT TO of the
  session), then with `rep.OriginalEnvelopeID`, then with
  `rep.OriginalHeader("X-...-Email-ID")`, in that order. Never decide from a
  recipient address alone.
- `verp` ids hold `a-z`, `0-9`, `-` and `_` because a mail system may change the
  case of a local part. Keep the keys in a list: put the new one first when you
  rotate and keep the old one until its mail stops coming back.

## Records and verification

```go
records, err := dnsauth.Records(dnsauth.Config{Domain: d, DKIMSelector: s, DKIMPublicKey: pub,
	InboundHost: host, SPFMechanisms: []string{"include:spf.example.net"}})
checked := dnsauth.Verify(ctx, dnsauth.DefaultResolver(), records, dnsauth.VerifyOptions{})
status := dnsauth.Overall(checked)
```

- Show `Name`, `Type`, `Value`, `TTL`, `Priority` and `Status` as they are: they
  are the columns customers know. The DMARC record is `Recommended`; the
  domain works without it and `Overall` ignores it.
- Verify on a schedule, with `FailMissing: false` while the customer is still
  publishing, and `true` once the time you allow has run out.
- Tests use `dnsauth.NewFake()`; never the network.

## What not to do

- Do not build a message with `fmt.Sprintf` and a template of headers.
- Do not read a message with `strings.Split(raw, "\r\n\r\n")`.
- Do not verify DKIM or SPF by calling `net.LookupTXT` directly: pass a
  `Resolver`.
- Do not catch `mime.ErrHeaderInjection` and retry with the value cleaned.
- Do not put a real person's address, a real customer's domain or a private key
  in a test or in a log.
