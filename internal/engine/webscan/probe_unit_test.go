package webscan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPayloadShape: every generated marker and payload matches the
// alphabet. (D1, static half; the runtime half is TestPayloadRuntime.)
func TestPayloadShape(t *testing.T) {
	for i := 0; i < 500; i++ {
		m, err := makeMarker()
		if err != nil {
			t.Fatal(err)
		}
		if !AllowedPayloadRe.MatchString(m) || !AllowedPayloadRe.MatchString(probePayload(m)) {
			t.Fatalf("bad payload: %q", probePayload(m))
		}
	}
	for _, bad := range []string{"scnrZZZZZZZZZZZZ", "scnr0123456789ab' OR '1'='1", "scnr0123456789ab<script>", "xscnr0123456789ab", ""} {
		if AllowedPayloadRe.MatchString(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// TestProbeSourceHygiene (D1, AST half): no string literal is ever passed
// as a query value in probe.go — payloads are only ever built by
// probePayload/canaryOrigin at run time — and RawQuery is only ever
// assigned from Values.Encode, never concatenated.
func TestProbeSourceHygiene(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "probe.go"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "probe.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Set" || sel.Sel.Name == "Add") && len(call.Args) == 2 {
			if lit, ok := call.Args[1].(*ast.BasicLit); ok {
				t.Errorf("literal query value %s passed to .%s", lit.Value, sel.Sel.Name)
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "RawQuery" {
				for _, rhs := range assign.Rhs {
					if _, ok := rhs.(*ast.CallExpr); !ok {
						t.Errorf("RawQuery assigned from non-call: %T", rhs)
					}
				}
			}
		}
		return true
	})
}

// TestReflectionClassification (D8, table half): HTML text and attribute
// reflection is a finding; JSON bodies, script literals and comments are
// not; encoded quotes are informational.
func TestReflectionClassification(t *testing.T) {
	marker := "scnr0123456789ab"
	payload := probePayload(marker)
	html := "text/html; charset=utf-8"
	cases := []struct {
		name string
		body string
		ct   string
		want reflectKind
	}{
		{"text", "<html><body><p>hi " + payload + "</p></body></html>", html, reflectHTML},
		{"attribute", `<html><body><input value="` + payload + `"></body></html>`, html, reflectHTML},
		{"json", `{"q": "` + payload + `"}`, "application/json", reflectNone},
		{"missing content type", "<p>" + payload + "</p>", "", reflectNone},
		{"script string", "<html><script>var q=\"" + payload + "\";</script><p>x</p></html>", html, reflectNone},
		{"script closed then html", "<html><script>var a=1;</script><p>" + payload + "</p></html>", html, reflectHTML},
		{"comment", "<html><!-- " + payload + " --><p>x</p></html>", html, reflectNone},
		{"absent", "<html><p>no marker here</p></html>", html, reflectNone},
		{"encoded", "<html><p>hi " + marker + "&#x27;&quot;&lt;</p></html>", html, reflectEscaped},
		{"marker bare no entities", "<html><p>hi " + marker + "</p></html>", html, reflectNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, at := classifyReflection([]byte(c.body), c.ct, marker, payload)
			if got != c.want {
				t.Fatalf("got %d want %d", got, c.want)
			}
			if got != reflectNone && !strings.Contains(c.body, marker) {
				t.Fatalf("match at %d but marker absent", at)
			}
		})
	}
}

func TestStableLocationHasNoValues(t *testing.T) {
	u := mustURL(t, "https://app.example/search?q=hello&lang=en")
	if got := stableLocation(u, "q"); got != "https://app.example/search?q" {
		t.Fatalf("%q", got)
	}
	if got := displayURL(u, "q", "scnr0123456789ab'\"<"); !strings.HasPrefix(got, "/search?q=") || strings.Contains(got, "hello") {
		t.Fatalf("%q", got)
	}
}
