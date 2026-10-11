package aws

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sdkOps walks every non-test source of this package and returns the SDK
// operations it names, as "service:Op", by file: <svc>.<Op>Input literals
// and <svc>.New<Op>Paginator constructors on an imported
// aws-sdk-go-v2/service/<svc> package. Operations the code could issue
// without naming an Input type do not exist in the SDK (every call takes
// its *<Op>Input), so this is complete.
func sdkOps(t *testing.T) map[string][]string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	out := map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		svcs := map[string]string{} // local name -> service
		for _, im := range node.Imports {
			p := strings.Trim(im.Path.Value, `"`)
			if !strings.HasPrefix(p, "github.com/aws/aws-sdk-go-v2/service/") || strings.HasSuffix(p, "/types") {
				continue
			}
			svc := p[strings.LastIndex(p, "/")+1:]
			name := svc
			if im.Name != nil {
				name = im.Name.Name
			}
			svcs[name] = svc
		}
		if len(svcs) == 0 {
			continue
		}
		ast.Inspect(node, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			svc, ok := svcs[id.Name]
			if !ok {
				return true
			}
			name := sel.Sel.Name
			switch {
			case strings.HasSuffix(name, "Input"):
				out[f] = append(out[f], svc+":"+strings.TrimSuffix(name, "Input"))
			case strings.HasPrefix(name, "New") && strings.HasSuffix(name, "Paginator"):
				out[f] = append(out[f], svc+":"+strings.TrimSuffix(strings.TrimPrefix(name, "New"), "Paginator"))
			}
			return true
		})
	}
	return out
}

// B2: every SDK operation named in source is read-only; the credential
// files may name exactly the credential operations; the union equals the
// published Operations list (which feeds `scnr config show --aws-policy`).
func TestAWSOperationsAreReadOnly(t *testing.T) {
	ops := sdkOps(t)
	if len(ops) == 0 {
		t.Fatal("no SDK operations found")
	}
	seen := map[string]bool{}
	for file, list := range ops {
		for _, op := range list {
			svc, name, _ := strings.Cut(op, ":")
			seen[IAMAction(op)] = true
			if (file == "client.go" || file == "creds.go") && svc == "sts" {
				if !credentialOps[name] {
					t.Errorf("%s: STS operation %s is not in credentialOps", file, name)
				}
				continue
			}
			if !readOnlyOp.MatchString(name) || readOnlyDeny[name] {
				t.Errorf("%s: operation %s is not read-only", file, op)
			}
		}
	}
	// AssumeRole* are issued by the SDK's stscreds providers, not named
	// here, and are not IAM actions the scanner policy needs for the
	// posture calls themselves.
	var got []string
	for op := range seen {
		got = append(got, op)
	}
	sort.Strings(got)
	want := append([]string(nil), Operations...)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Operations drifted from the sources.\n got: %v\nwant: %v", got, want)
	}
	t.Logf("operations (IAM policy actions):\n  %s", strings.Join(want, "\n  "))
}

// forbiddenSelectors returns the selector names in file that are on the
// forbidden list (field reads the checks must never make).
func forbiddenSelectors(t *testing.T, file string, forbidden []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]bool{}
	for _, f := range forbidden {
		bad[f] = true
	}
	var out []string
	ast.Inspect(node, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && bad[sel.Sel.Name] {
			out = append(out, sel.Sel.Name)
		}
		return true
	})
	return out
}
