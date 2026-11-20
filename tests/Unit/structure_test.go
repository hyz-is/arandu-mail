package unit_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowedModules are the import prefixes outside the standard library that
// production code may name: this module's own packages, and golang.org/x.
var allowedModules = []string{"github.com/hyz-is/arandu-mail/", "golang.org/x/"}

// packages are the library packages and what each is documented to do.
var packages = []string{"mime", "dkim", "dsn", "arf", "verp", "dnsauth"}

// fuzzTargets are the parsers that must have a fuzz test, by package.
var fuzzTargets = map[string][]string{
	"mime":    {"FuzzParse", "FuzzParseAddressList", "FuzzDecodeWords", "FuzzParseMediaType", "FuzzBuilder"},
	"dkim":    {"FuzzVerify", "FuzzParseKeyRecord", "FuzzSignThenVerify"},
	"dsn":     {"FuzzParse", "FuzzClassify"},
	"arf":     {"FuzzParse"},
	"verp":    {"FuzzDecode"},
	"dnsauth": {"FuzzParseSPF", "FuzzCheckSPF", "FuzzParseDMARC", "FuzzParseMTASTSPolicy", "FuzzParseTLSRPT"},
}

// TestThePackageIsALibrary holds the shape of this repository: pure Go
// libraries that register nothing, own no table and decide no authorization.
func TestThePackageIsALibrary(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	for _, path := range []string{
		"module.go", "model.go", "policy.go", "service.go", "views.go", "config.go",
		"resources", "migrations", "database", "routes", "app", "bootstrap",
	} {
		if _, err := os.Lstat(filepath.Join(root, path)); err == nil {
			t.Errorf("%s exists; this package registers nothing, owns no table and decides no authorization", path)
		} else if !os.IsNotExist(err) {
			t.Errorf("checking %s: %v", path, err)
		}
	}

	refusedMethods := map[string]string{
		"Routes": "a route", "Migrations": "a table", "Boot": "a boot step",
		"Publishes": "a publication", "Authorize": "an authorization decision",
	}
	for _, source := range productionGoFiles(t, root) {
		for _, imported := range source.file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Errorf("%s has an unreadable import %s", source.path, imported.Path.Value)
				continue
			}
			first, _, _ := strings.Cut(path, "/")
			if !strings.Contains(first, ".") {
				continue // the standard library
			}
			allowed := false
			for _, prefix := range allowedModules {
				if strings.HasPrefix(path, prefix) {
					allowed = true
				}
			}
			if !allowed {
				t.Errorf("%s imports %s; production code may import the standard library, golang.org/x and this module", source.path, path)
			}
			if strings.Contains(path, "/arandu-io/") {
				t.Errorf("%s imports %s; an Arandu module imports no framework package", source.path, path)
			}
		}
		ast.Inspect(source.file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.TypeSpec:
				if node.Name.Name == "Module" || strings.HasSuffix(node.Name.Name, "ServiceProvider") {
					t.Errorf("%s declares %s; there is nothing to register", source.path, node.Name.Name)
				}
			case *ast.FuncDecl:
				if what, refused := refusedMethods[node.Name.Name]; refused && node.Recv != nil {
					t.Errorf("%s declares %s.%s, which is %s this package does not have",
						source.path, receiverType(node), node.Name.Name, what)
				}
				if node.Recv == nil && node.Name.Name == "init" {
					t.Errorf("%s declares init; a library does work only when it is called", source.path)
				}
			}
			return true
		})
	}
}

// TestEveryPackageIsDocumentedAndTested holds what each package must carry: a
// package comment, tests, a benchmark where bytes are processed, and a fuzz
// test for each parser.
func TestEveryPackageIsDocumentedAndTested(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	for _, name := range packages {
		dir := filepath.Join(root, name)
		doc, err := os.ReadFile(filepath.Join(dir, "doc.go"))
		if err != nil {
			t.Errorf("%s has no doc.go: %v", name, err)
		} else if !strings.Contains(string(doc), "// Package "+name+" ") {
			t.Errorf("%s/doc.go does not open with a package comment", name)
		}

		tests := ""
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), "_test.go") {
				body, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				tests += string(body)
			}
		}
		if tests == "" {
			t.Errorf("%s has no tests", name)
			continue
		}
		for _, fuzz := range fuzzTargets[name] {
			if !strings.Contains(tests, "func "+fuzz+"(") {
				t.Errorf("%s has no fuzz test %s", name, fuzz)
			}
		}
		if !strings.Contains(tests, "func Benchmark") {
			t.Errorf("%s has no benchmark", name)
		}
	}
}

// TestNoPackageWritesToTheGlobalState keeps the packages free of mutable
// package-level state: a variable that is assigned after initialization is a
// registry, and a library that has one is not safe to share.
func TestNoPackageWritesToTheGlobalState(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	for _, source := range productionGoFiles(t, root) {
		globals := map[string]bool{}
		for _, decl := range source.file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				for _, name := range spec.(*ast.ValueSpec).Names {
					globals[name.Name] = true
				}
			}
		}
		for _, decl := range source.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				assign, ok := n.(*ast.AssignStmt)
				if !ok || assign.Tok == token.DEFINE {
					return true
				}
				for _, lhs := range assign.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && globals[id.Name] && !shadowed(fn, id.Name) {
						t.Errorf("%s: %s assigns the package variable %s", source.path, fn.Name.Name, id.Name)
					}
				}
				return true
			})
		}
	}
}

// shadowed reports whether the function declares a local of that name.
func shadowed(fn *ast.FuncDecl, name string) bool {
	found := false
	check := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, f := range fields.List {
			for _, n := range f.Names {
				if n.Name == name {
					found = true
				}
			}
		}
	}
	check(fn.Type.Params)
	check(fn.Type.Results)
	check(fn.Recv)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
						found = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, id := range n.Names {
				if id.Name == name {
					found = true
				}
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{n.Key, n.Value} {
				if id, ok := e.(*ast.Ident); ok && id.Name == name {
					found = true
				}
			}
		}
		return true
	})
	return found
}

// TestTheGuidesTeachTheLibrary keeps the documents an installer and a
// maintainer read in step with the package that exists.
func TestTheGuidesTeachTheLibrary(t *testing.T) {
	t.Parallel()

	root := packageRoot(t)
	guides := map[string][]string{
		"README.md": {"go get github.com/hyz-is/arandu-mail", "arandu-mail/mime", "arandu-mail/dkim", "arandu-mail/dsn",
			"arandu-mail/arf", "arandu-mail/verp", "arandu-mail/dnsauth", "dnsauth.Records", "dsn.Classify", "mime.NewBuilder"},
		"AGENTS.md": {"TestThePackageIsALibrary", "GOWORK=off", "-fuzz", "mime", "dkim", "dsn", "arf", "verp", "dnsauth"},
		".agents/skills/mail-package/SKILL.md": {"go get github.com/hyz-is/arandu-mail", "mime.NewBuilder", "dkim.NewSigner",
			"dsn.Classify", "verp.New", "dnsauth.Records"},
		".agents/skills/mail-release/SKILL.md": {"FuzzParse", "TestTheModuleRequiresOnlyTheStandardLibraryAndX"},
		".agents/skills/README.md":             {"mail-package", "mail-release", "mail-vault-notes"},
	}
	retired := []string{
		"mail.New(", "mail.Config{", "MailService", "MailPolicy", "Mails(",
		"model:build", "vendor:publish", "/auth/login",
	}

	for path, required := range guides {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)
		for _, want := range required {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not teach %q", path, want)
			}
		}
		for _, stale := range retired {
			if strings.Contains(text, stale) {
				t.Errorf("%s still teaches the template's module through %q", path, stale)
			}
		}
	}
}

// TestEverySkillIsNamedAfterItsDirectory holds the one line of a skill that a
// tool reads as data, and which skill an application receives.
func TestEverySkillIsNamedAfterItsDirectory(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(packageRoot(t), ".agents", "skills")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the skills: %v", err)
	}
	var found []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		found = append(found, entry.Name())
		body, err := os.ReadFile(filepath.Join(dir, entry.Name(), "SKILL.md"))
		if err != nil {
			t.Errorf("%s has no SKILL.md: %v", entry.Name(), err)
			continue
		}
		text := string(body)
		if !strings.HasPrefix(text, "---\nname: "+entry.Name()+"\n") {
			t.Errorf("%s/SKILL.md does not open with name: %s", entry.Name(), entry.Name())
		}
		forApplications := strings.Contains(text, "\nmetadata:\n  audience: app\n")
		if want := entry.Name() == "mail-package"; forApplications != want {
			t.Errorf("%s: audience app = %v, want %v", entry.Name(), forApplications, want)
		}
	}
	sort.Strings(found)
	if strings.Join(found, ",") != "mail-package,mail-release,mail-vault-notes" {
		t.Errorf("skills = %v, want mail-package, mail-release and mail-vault-notes", found)
	}
}

type parsedGoFile struct {
	path string
	file *ast.File
}

func productionGoFiles(t *testing.T, root string) []parsedGoFile {
	t.Helper()

	files := []parsedGoFile{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") || strings.HasSuffix(entry.Name(), ".kyse.go") {
			return nil
		}
		// The comments are kept because a build constraint is one, and a file
		// the compiler never reads is not part of what this package does.
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, parsedGoFile{path: filepath.ToSlash(relative), file: file})
		return nil
	})
	if err != nil {
		t.Fatalf("reading production Go files: %v", err)
	}
	return files
}

func receiverType(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return ""
	}
	return namedType(function.Recv.List[0].Type)
}

func namedType(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.StarExpr:
		return namedType(expression.X)
	case *ast.SelectorExpr:
		return expression.Sel.Name
	case *ast.IndexExpr:
		return namedType(expression.X)
	case *ast.IndexListExpr:
		return namedType(expression.X)
	default:
		return ""
	}
}

func packageRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("finding package root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
