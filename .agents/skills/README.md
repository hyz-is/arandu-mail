# Skills

Procedures an assistant follows when working on this package.

They live in `.agents/skills/<name>/SKILL.md`, which is the path the coding
assistants read from. It is one directory rather than a file per vendor, so a
skill written once is read by whatever this package is being written with.

Each file opens with frontmatter carrying a `name` and a `description`. The
`name` has to equal the directory name exactly, or the skill is not loaded. The
description is what a tool reads to decide whether the skill is relevant, so it
names the situation you are in rather than the topic it covers.

| skill | when it fires |
| --- | --- |
| `mail-release` | the gates, the fuzz and benchmark runs, the manifest, a dependency, a version, a tag |
| `mail-vault-notes` | writing the note, the gap or the journal entry, when this checkout sits inside the Arandu Obsidian vault |
| `mail-package` | building, reading or signing a message, reading a bounce, writing a return path or checking DNS records **in an application** |

The template this package started from carried a `-policy` and a `-module`
skill. Both taught the HTTP module the template ships, and this package removed
it: there is no policy to open and no route, handler or migration to add.

`mail-package` has a different audience from the other two, and that is on
purpose: it travels with the package so that an assistant working in somebody
else's project, the one running `go get`, has the packages, the calls and the
mistakes in front of it instead of writing a MIME builder of its own. Its
frontmatter says so under `metadata`, with `audience: app`, which is what
`aru skills:sync` reads to copy the skill into an application whose `go.mod`
requires this package. No other skill here carries it.

`mail-vault-notes` fires on a condition rather than on a task: it applies only
when `MOC-arandu.md`, `plans/cmd/audit-vault/` and `45-modules/` are actually
beside this checkout. Outside the vault it is inert.

## Why these exist

The common failure modes when changing this package are a value cleaned instead
of refused on its way to a header, an allocation added to a path that did not
have one, a parser with no fuzz test, a canonicalization changed until the RFC
vectors stop agreeing, a dependency added, and a real address or key pasted into
a test. None belongs here.

## Adding your own

A skill in this directory is yours and travels with the repository. Keep it a
procedure rather than a description: a file that says "read the documentation"
never changes what anybody does.
