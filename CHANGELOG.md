# Changelog

Everything worth knowing about a release of Arandu Mail is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- `mime`: `Builder` for messages (From, To, Cc, Bcc, Reply-To, Subject, text,
  HTML, attachments, inline images by Content-ID, custom headers, Message-ID and
  Date, `List-Unsubscribe` and `List-Unsubscribe-Post`), with
  multipart/alternative, related and mixed, a transfer encoding chosen from the
  content, RFC 2047 encoded words, RFC 2231 parameters, Punycode domains,
  SMTPUTF8 local parts, lines of at most 998 octets with CRLF, and refusal of a
  CR, LF or NUL in any header value. `Parse`, `ParseBytes` and `ParseEntity`
  read RFC 5322 and MIME into addresses, bodies, attachments, headers and the
  MIME tree, with UTF-8, US-ASCII, ISO-8859-1, ISO-8859-15 and Windows-1252.
  `ParseAddressList`, `DecodeWords`, `ParseMediaType`, `ParseHeader`, and the
  helpers of an SMTP relay, `ResolveRecipients` and `ForwardableHeaders`.
- `dkim`: `GenerateKey`, `ParsePrivateKey`, `KeyPair.TXT`; `Signer` for
  RSA-SHA256 and Ed25519-SHA256 with simple and relaxed canonicalization, the
  recommended header list and oversigning of From, To and Subject; `Verifier`
  with a `Resolver` interface; `ParseKeyRecord`. Tested with the keys and the
  signed message of RFC 8463 and the examples of RFC 6376.
- `dsn`: `Parse` for RFC 3464 reports and for bounces that are not standard,
  `Classify` and `Recipient.Classification` in the SES vocabulary (Permanent,
  Transient, Undetermined; General, NoEmail, Suppressed, MailboxFull,
  MessageTooLarge, ContentRejected, AttachmentRejected).
- `arf`: `Parse` for RFC 5965 feedback reports, with the Message-ID and the
  custom email id header of the returned original.
- `verp`: `Codec` that writes and reads `bounces+<id>.<tag>@<domain>` with an
  HMAC tag and key rotation.
- `dnsauth`: `Records` and `Verify` for the DKIM, SPF, MX and DMARC records of
  a sending domain with the statuses of the useSend dashboard; `SPFChecker`
  (RFC 7208 check_host); `ParseDMARC`, `LookupDMARC`, `EvaluateDMARC`;
  `LookupMTASTS` and `ParseMTASTSPolicy`; `ParseTLSRPT` and `LookupTLSRPT`;
  the `Resolver` and `HTTPClient` interfaces and an in-memory `Fake` resolver.
- A fuzz test for every parser, benchmarks for every package, and examples that
  run as tests.
