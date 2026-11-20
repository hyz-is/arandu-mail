# Working on Arandu Mail

This is an Arandu package made of pure Go libraries for the protocols a mail
platform speaks: building and reading messages (`mime`), DKIM (`dkim`), bounces
(`dsn`), feedback reports (`arf`), bounce addresses (`verp`) and the DNS side of
authentication (`dnsauth`). It is a Go module somebody `go get`s and imports.

It began as the package skeleton, configured as `hyz-is/mail`, and the HTTP
module the template ships was removed on purpose: there is no entity, no table,
no migration, no policy, no route, no view and no `Module` to register. Nothing
here should grow back into one.

Read `.agents/skills/` before writing code. Each skill is a procedure, and the
one you need is named by the situation you are in.

## The gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` is not a preference. This checkout may sit beside a Go workspace
that lists the framework repositories and does not list this one; when it does,
every command above fails before it compiles anything:

```
pattern ./...: directory prefix . does not contain modules listed in go.work
or their selected dependencies
```

Before a release, give each parser a longer fuzz run. The seeds and the inputs
that once found a defect run on every `go test`; the run is what looks past
them:

```sh
go test ./mime -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./mime -run='^$' -fuzz='^FuzzParseAddressList$' -fuzztime=60s
go test ./mime -run='^$' -fuzz='^FuzzBuilder$' -fuzztime=60s
go test ./dkim -run='^$' -fuzz='^FuzzVerify$' -fuzztime=60s
go test ./dkim -run='^$' -fuzz='^FuzzSignThenVerify$' -fuzztime=60s
go test ./dsn -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./arf -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./verp -run='^$' -fuzz='^FuzzDecode$' -fuzztime=60s
go test ./dnsauth -run='^$' -fuzz='^FuzzParseSPF$' -fuzztime=60s
go test ./dnsauth -run='^$' -fuzz='^FuzzCheckSPF$' -fuzztime=60s
```

A fuzz failure writes its input under `testdata/fuzz/<Target>/`. Commit that
file with the fix: it is the regression test.

`aru doctor` is not one of the gates. It reads applications, and exits 1 here.
It does not read this package after it is installed either, which is why
`tests/Unit/audit_test.go` compares `arandu.mod.toml` with what the code calls.

## What this repository holds

| | measured with |
| --- | --- |
| 6 packages, `mime`, `dkim`, `dsn`, `arf`, `verp` and `dnsauth`, and `internal/puny` | `ls -d */` |
| 0 routes, 0 tables, 1 capability (`network`, for `dnsauth`) | `arandu.mod.toml`, `TestThePackageIsALibrary` |
| 1 direct dependency, `golang.org/x/net`, for the public suffix list | `go list -m -f '{{if and (not .Indirect) (not .Main)}}{{.Path}} {{.Version}}{{end}}' all` |
| a fuzz test for every parser, a benchmark for every package | `tests/Unit/structure_test.go` |

```
mime/      builder.go fold.go encoding.go charset.go params.go address.go header.go parse.go
dkim/      key.go canon.go signer.go verifier.go tags.go
dsn/       dsn.go classify.go
arf/       arf.go
verp/      verp.go
dnsauth/   resolver.go records.go spf.go dmarc.go mtasts.go
internal/puny   Punycode for the domains of addresses and signing domains
tests/Unit      the audit of the manifest and the shape of the library
```

## What does not exist here, on purpose

| A model reaches for | What is here instead |
| --- | --- |
| a `Module`, a route, a `Config` for the whole package, a line in `k.Register` | nothing. A caller imports the package it needs and builds the value it wants |
| a third-party MIME, DKIM, SPF or DNS library | the code in this repository, written from the RFCs. The standard library and `golang.org/x` are the only imports |
| `init` that registers something, a package variable that is assigned later | values built by `New...` and passed explicitly. `TestNoPackageWritesToTheGlobalState` and `TestThePackageIsALibrary` refuse both |
| a DNS lookup with `net.LookupTXT` called directly | the `Resolver` interface, so a test answers without the network |
| an HTTP fetch with `http.Get` | the `HTTPClient` interface, with no redirect |
| trusting a header value because it came from our own caller | `checkText` on every value that reaches a header or a parameter: a CR, LF or NUL is an error |
| a real person's address, a real domain's key or a real customer's mail in a test | `example.com`, `example.net` and the documentation addresses, and the RFC 8463 keys, which are published for testing |
| copying code from another mail library | nothing. The behaviour of the useSend SMTP relay and of its SES hook parser was read to match the vocabulary, not copied |

## The properties

A change that breaks one of them is not merged, whatever else it improves.

1. **Wire output is clean.** `Build` writes CRLF only, no NUL, no line over 998
   octets, no header that the caller did not ask for. `FuzzBuilder` holds it
   against the standard library parser.
2. **Hot paths do not allocate with the size of the message.** The builder, the
   canonicalizers and the signer write into a buffer the caller or a pool owns.
   A change that adds an allocation per byte, per line or per part shows in the
   benchmarks of the package; read them before and after.
3. **Parsers never panic and never loop.** Every parser has a fuzz test, a size
   or depth limit where input can nest, and returns an error rather than a
   guess when the input is not what it claims.
4. **The signature verifies against the RFC.** The DKIM tests use the keys and
   the signed messages of RFC 8463 and the canonicalization examples of
   RFC 6376. A change to canonicalization that those disagree with is a bug in
   the change.
5. **SPF stays inside its limits.** 10 DNS-querying terms, 2 void lookups, 10
   MX names. `FuzzCheckSPF` holds the number of lookups.
6. **`arandu.mod.toml` matches the code.** `network` is true because `dnsauth`
   calls out; the other three are false, and `tests/Unit/audit_test.go`
   compares them with what the code calls.

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, and the names and messages of tests.

Every exported symbol carries a doc comment, and the comment documents the
symbol and nothing else. Why a signature is what it is belongs there when it is
a fact about the code. A date, an issue number, a version in progress or the
name of another repository does not.

A new standard goes where it belongs: DNS-published policy in `dnsauth`,
anything in a message in `mime`, anything about a signature in `dkim`. A
capability that none of them covers is a new package here only if it is a
protocol; a delivery engine or a server belongs to its own module.

## Commits

One commit per logical change, in English, saying what changed and why. The
identity is `HYZIS <admin@hyz.is>` and is set in this repository's own git
config. Never any AI attribution. `core.hooksPath` points at
`/Users/paulorlima9/Developer/arandu-io/.githooks`.

Push, creating the repository on GitHub and tagging are for Paulo to authorize.
The repository is created from `arandu-io/package-skeleton` in the `hyz-is`
organization, and the work done here is rebased onto its first commit.
