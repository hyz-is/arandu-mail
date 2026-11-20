package unit_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTheModuleRequiresOnlyTheStandardLibraryAndX holds the dependency policy
// of an Arandu module that is a library: the standard library and golang.org/x,
// nothing else. The module is compiled into other people's builds, so every
// further require is a download and an audit surface for each of them.
func TestTheModuleRequiresOnlyTheStandardLibraryAndX(t *testing.T) {
	goMod := readReleaseFile(t, packageRoot(t), "go.mod")

	required := regexp.MustCompile(`(?m)^(?:require\s+|\t)([a-z0-9.\-]+\.[a-z]+/\S+)\s+v\S+(\s*//\s*indirect)?\s*$`).
		FindAllStringSubmatch(goMod, -1)
	for _, requirement := range required {
		if !strings.HasPrefix(requirement[1], "golang.org/x/") {
			t.Errorf("go.mod requires %s; this module takes the standard library and golang.org/x only", requirement[1])
		}
	}
	if strings.Contains(goMod, "replace") {
		t.Error("go.mod has a replace directive; a module never points at a local checkout")
	}
}

// TestTheManifestDeclaresAFrameworkFloor keeps the floor an installer reads.
func TestTheManifestDeclaresAFrameworkFloor(t *testing.T) {
	manifest := readReleaseFile(t, packageRoot(t), "arandu.mod.toml")
	captureReleaseValue(t, manifest, `(?m)^framework = ">= ([0-9]+\.[0-9]+)"$`, "Framework floor in arandu.mod.toml")
	captureReleaseValue(t, manifest, `(?m)^name = "hyz-is/mail"$`, "the module name in arandu.mod.toml")
}

func TestTheReleaseSkillUsesTheManifestFrameworkFloor(t *testing.T) {
	root := packageRoot(t)
	manifest := readReleaseFile(t, root, "arandu.mod.toml")
	skill := readReleaseFile(t, root, ".agents/skills/mail-release/SKILL.md")
	declared := captureReleaseValue(t, manifest,
		`(?m)^framework = ">= ([0-9]+\.[0-9]+)"$`,
		"Framework floor in arandu.mod.toml")

	want := `framework = ">= ` + declared + `"`
	if !strings.Contains(skill, want) {
		t.Fatalf("release skill does not teach manifest floor %q", want)
	}
}

// TestEveryChangelogVersionHasUpgradeNotes keeps the two files describing the
// same set of releases.
func TestEveryChangelogVersionHasUpgradeNotes(t *testing.T) {
	root := packageRoot(t)
	changelog := readReleaseFile(t, root, "CHANGELOG.md")
	upgrade := readReleaseFile(t, root, "UPGRADE.md")

	inChangelog := regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - `).FindAllStringSubmatch(changelog, -1)
	inUpgrade := regexp.MustCompile(`(?m)^## v([0-9]+\.[0-9]+\.[0-9]+)$`).FindAllStringSubmatch(upgrade, -1)
	if len(inChangelog) == 0 && len(inUpgrade) == 0 {
		t.Skip("nothing released yet: neither file has a version heading")
	}

	versions := func(matches [][]string) map[string]bool {
		out := map[string]bool{}
		for _, m := range matches {
			out[m[1]] = true
		}
		return out
	}
	logged, upgraded := versions(inChangelog), versions(inUpgrade)
	for v := range logged {
		if !upgraded[v] {
			t.Errorf("CHANGELOG.md has %s and UPGRADE.md has no notes for it", v)
		}
	}
	for v := range upgraded {
		if !logged[v] {
			t.Errorf("UPGRADE.md has notes for %s and CHANGELOG.md has no entry for it", v)
		}
	}
}

// TestTheChangelogNamesEveryPackage keeps the first entry honest about what
// the module holds: a package that went out undocumented is one nobody knows
// to use.
func TestTheChangelogNamesEveryPackage(t *testing.T) {
	changelog := readReleaseFile(t, packageRoot(t), "CHANGELOG.md")
	for _, name := range packages {
		if !strings.Contains(changelog, "`"+name+"`") {
			t.Errorf("CHANGELOG.md does not name the package `%s`", name)
		}
	}
}

func TestCIGuardsIncompatibleAPIChanges(t *testing.T) {
	ci := readReleaseFile(t, packageRoot(t), ".github/workflows/ci.yml")
	required := []string{
		"fetch-depth: 0",
		"name: api diff against the last release",
		`modpath=$(GOWORK=off go list -m -f '{{.Path}}')`,
		`git show "${tag}:go.mod"`,
		"git worktree add",
		"golang.org/x/exp/cmd/apidiff@latest -m -w",
		"-m -incompatible",
		`git diff --quiet "$latest" -- UPGRADE.md`,
		`added=$(git diff "$latest" -- UPGRADE.md`,
	}
	for _, want := range required {
		if !strings.Contains(ci, want) {
			t.Errorf("CI does not contain the API compatibility gate %q", want)
		}
	}
}

func TestTheReleasePublishesThePreVersionedChangelogEntryOnce(t *testing.T) {
	root := packageRoot(t)
	release := readReleaseFile(t, root, ".github/workflows/release.yml")
	changelog := readReleaseFile(t, root, "CHANGELOG.md")

	seen := map[string]bool{}
	for _, heading := range regexp.MustCompile(`(?m)^## \[([0-9]+\.[0-9]+\.[0-9]+)\] - `).FindAllStringSubmatch(changelog, -1) {
		if seen[heading[1]] {
			t.Errorf("CHANGELOG.md has more than one %s heading", heading[1])
		}
		seen[heading[1]] = true
	}
	required := []string{
		`tags: ["v*"]`,
		"contents: write",
		`version="${TAG#v}"`,
		`heading="## [$version] - "`,
		`gh release create "$TAG"`,
		"--verify-tag",
		`--notes-file "$notes"`,
	}
	for _, want := range required {
		if !strings.Contains(release, want) {
			t.Errorf("release workflow does not contain %q", want)
		}
	}
	if got := strings.Count(release, `gh release create "$TAG"`); got != 1 {
		t.Errorf("release creation commands = %d, want exactly one", got)
	}
	for _, forbidden := range []string{
		"Write it into the changelog", "git commit", "git push", "git tag", "gh release delete", "CHANGELOG.next",
	} {
		if strings.Contains(release, forbidden) {
			t.Errorf("release workflow mutates the pre-versioned changelog through %q", forbidden)
		}
	}
}

func readReleaseFile(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(raw)
}

func captureReleaseValue(t *testing.T, body, pattern, label string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(match) < 1 {
		t.Fatalf("%s is missing", label)
	}
	if len(match) == 1 {
		return match[0]
	}
	return match[1]
}
