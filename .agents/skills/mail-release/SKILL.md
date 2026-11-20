---
name: mail-release
description: Get this Arandu package green, declared and published. Use when the request is to "run the gates", "the tests fail", "run the fuzzers", "run the benchmarks", "go build says the directory prefix does not contain modules listed in go.work", "update arandu.mod.toml", "add a dependency", "tag a release", "publish it", "write the changelog", "rebase onto the template commit", or before opening a pull request. Covers the four gates, the fuzz and benchmark runs, what the manifest declares and who checks it, the immutability of a published module version, and what breaks somebody else's build.
license: MIT
---

# Getting it green and out

## The four gates

Nothing is finished until all four exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
go vet ./...
go test -race ./...
```

`GOWORK=off` first. This checkout may sit beside a Go workspace that lists the
framework repositories and does not list this one. When it does, `go build ./...`
exits 1 before compiling anything:

```
pattern ./...: directory prefix . does not contain modules listed in go.work
or their selected dependencies
```

That is the workspace refusing to answer for a module it was not told about, and
it says nothing about the code. With the workspace off, the module resolves the
versions in `go.mod`, which is what CI compiles against and what somebody's
`go get` will get.

`aru doctor` is not a gate. It reads applications and exits 1 here.

## The fuzz runs

Every parser has a target. Before a release, run each one for a minute:

```sh
go test ./mime -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./dkim -run='^$' -fuzz='^FuzzVerify$' -fuzztime=60s
go test ./dsn -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./arf -run='^$' -fuzz='^FuzzParse$' -fuzztime=60s
go test ./dnsauth -run='^$' -fuzz='^FuzzCheckSPF$' -fuzztime=60s
```

`tests/Unit/structure_test.go` lists the targets that must exist
(`FuzzParse`, `FuzzParseAddressList`, `FuzzBuilder`, `FuzzSignThenVerify`,
`FuzzDecode`, `FuzzParseSPF`...). A failure writes its input under
`testdata/fuzz/<Target>/`; commit that file with the fix.

## The benchmarks

```sh
go test ./... -run='^$' -bench . -benchmem
```

Compare the allocations first: a hot path that starts allocating per byte or per
line is the regression, whatever the time says. Update the table in `README.md`
with what you measured, and say on what machine.

## What the manifest declares, and who reads it

```toml
name = "hyz-is/mail"
framework = ">= 0.66"
profiles = ["conventional", "performance"]

[permissions]
network = true
filesystem = false
exec = false
migrations = false
```

`arandu.mod.toml` is a promise, and the check that gives it weight runs here and
nowhere else: `aru doctor` audits the application it runs inside and never
loads a dependency. `TestTheDeclaredCapabilitiesAreWhatTheCodeDoes`, in
`tests/Unit/audit_test.go`, compares the four permissions with what the code
calls, by AST: `http.NewRequestWithContext`, `.Do`, `net.Dial`, `os.Open`,
`exec.Command`, a method named `Migrations`. `network = true` is for `dnsauth`,
which fetches an MTA-STS policy; if that call goes away, so does the
declaration, in the same commit.

The `framework` line is a floor. This package imports no framework package; the
floor is the template's and moves only when a release needs a newer one.

## Adding a dependency

Do not. This module takes the standard library and `golang.org/x` and nothing
else, and `TestTheModuleRequiresOnlyTheStandardLibraryAndX` fails the build on
anything more. If something has to come in from `golang.org/x`, say in the pull
request what it does that the standard library does not.

## Publishing

A published Go module version is **immutable**: a mistake is corrected by
another release, never by moving a tag. Public names are confirmed with Paulo
before anything is created or published.

The repository is created in the `hyz-is` organization from the template:

```sh
gh repo create hyz-is/arandu-mail --public --template arandu-io/package-skeleton
```

The work done before the repository existed is rebased onto the first commit,
the template commit made by hyz.is; the package is never published from a
repository started with `git init` elsewhere.

Before tagging:

- the four gates pass with `GOWORK=off`, and the fuzz runs are clean;
- `arandu.mod.toml` matches the code;
- `CHANGELOG.md` has the entry under the version, in the Keep a Changelog
  sections, and `UPGRADE.md` has the matching `## vX.Y.Z` heading;
- the release is tagged from the commit that holds both.

While the version starts with `v0.`, breaking is allowed. Breaking *quietly* is
not: a function that stops existing is a build that stops in somebody else's
repository, weeks later. Say what it was, what it is, and what they have to
write instead, in `UPGRADE.md`; the CI step `api diff against the last release`
fails unless every removal is named there.
