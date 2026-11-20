# Security policy

## Supported versions

The latest minor release of Arandu Mail receives security fixes. Older minor
releases do not: a published Go module version is immutable, so a fix is a new
release rather than a moved tag.

## Reporting a vulnerability

Report it privately, through GitHub's advisory form:

<https://github.com/hyz-is/arandu-mail/security/advisories/new>

Do not open a public issue and do not describe the problem in a pull request.
A report that arrives in public is a report every reader of this repository can
act on before there is a release to upgrade to.

Include what you need to reproduce it: the version, the input, and the call
or call that triggers it.

Expect an acknowledgement within a few days. If the report is confirmed, the
fix, the release and the advisory are published together, and you are credited
unless you ask not to be.

## What is in scope

Anything that lets input from the network or from a message do what it should
not. In particular:

- header injection: a value that reaches a header or a MIME parameter of a
  message built by `mime` and puts a CR, LF or NUL, or a second header, in it;
- a message, report or record that makes a parser panic, loop, or allocate
  without a bound (`mime`, `dsn`, `arf`, `dnsauth`);
- a DKIM signature that verifies when the message changed, an RSA key under
  1024 bits that is accepted, a body-length tag that lets text be appended
  without the verifier saying so, or a key record read as a different key than
  the one published;
- a `verp` address that decodes without having been made with a known key;
- an SPF evaluation that passes the limits of RFC 7208 (more than 10
  DNS-querying terms, more than 2 void lookups, a cycle that does not stop);
- an MTA-STS policy accepted over a redirect, over a wrong content type or past
  64 KiB.

## What is not

- A vulnerability in the Go standard library or in `golang.org/x`. Report that
  to the Go project.
- A message that is accepted but is spam or phishing: this package builds and
  reads messages and does not judge them.
- A DNS answer that is wrong because the resolver was poisoned: the `Resolver`
  the application passes in decides what is believed.
