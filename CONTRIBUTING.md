# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the four gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

The two filters on `gofmt` are not preference. `gofmt` is the only tool in the
chain that ignores build tags, so it reads files the compiler deliberately
excludes; `testdata/` holds fixtures that are invalid on purpose.

## What a change has to keep true

Six properties are the reason this package is what it is. A change that breaks
one of them will not be merged, whatever else it improves.

1. **Wire output is clean.** The builder writes CRLF only, no NUL, no line over
   998 octets, and nothing in a header that the caller did not ask for. A CR, LF
   or NUL in a value is an error.
2. **Hot paths do not allocate with the size of the message.** Run the
   benchmarks of the package before and after a change to the builder, the
   canonicalizers or the signer, and say what moved.
3. **Parsers never panic and never loop.** A new parser comes with a fuzz test,
   and the input of a fuzz failure is committed under `testdata/fuzz` with the
   fix.
4. **DKIM agrees with the RFC.** The tests use the keys and the signed message of
   RFC 8463 and the examples of RFC 6376; a change they disagree with is a bug.
5. **SPF stays inside its limits:** 10 DNS-querying terms, 2 void lookups and 10
   MX names.
6. **`arandu.mod.toml` matches the code.** Adding an outbound call, a file
   write or a process means declaring it there in the same commit.

The module takes the standard library and `golang.org/x` and nothing else, and
registers nothing: no `init`, no package variable assigned later, no `Module`.

A test never uses a real person's address, a real domain's key or a real
customer's mail. `example.com`, `example.net` and the published keys of the RFCs
are what fixtures are made of.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.
`pkg.go.dev` publishes the doc comments, and its readers are users of this
package.

Every exported symbol carries a doc comment saying what it does. The comment
documents the symbol and nothing else: no dates, no issue numbers, no
references to other repositories. Why a signature is what it is belongs there
when it is a fact about the code; anything else belongs in the pull request.

## Commits

One commit per logical change. Formatting is not mixed with behaviour, because
a diff that does both is a diff nobody reviews.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-mail.
