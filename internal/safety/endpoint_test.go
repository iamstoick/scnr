package safety

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndpointClientAllowlist: the endpoint client reaches only its declared
// hosts, refuses other hosts (private ones included) and refuses redirects
// off the allowlist with RedirectOutOfScopeError.
func TestEndpointClientAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			// Another loopback address: private, not on the allowlist, and
			// refused before any dial.
			http.Redirect(w, r, "http://127.0.0.2:1/x", http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	host := mustHost(t, srv.URL)
	c, err := NewEndpointClient([]string{host}, HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("allowed host: %v", err)
	}
	resp.Body.Close()
	// A different address is refused even though it is private (the scope
	// check runs before any dial, so the unroutable port is never reached).
	if _, err := c.Get("http://127.0.0.2:1/"); err == nil || !strings.Contains(err.Error(), CodeScopeNotAllowed) {
		t.Fatalf("other private host should be refused, got %v", err)
	}
	if _, err := c.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !strings.Contains(err.Error(), "E_SCOPE") {
		t.Fatalf("metadata endpoint should be refused, got %v", err)
	}
	_, err = c.Get(srv.URL + "/redirect")
	if _, ok := AsRedirectOutOfScope(err); !ok {
		t.Fatalf("redirect off the allowlist should be RedirectOutOfScopeError, got %v", err)
	}
	if _, err := NewEndpointClient(nil, HTTPOptions{}); err == nil {
		t.Fatal("empty host list accepted")
	}
	if _, err := NewEndpointClient([]string{"a b"}, HTTPOptions{}); err == nil {
		t.Fatal("bad host accepted")
	}

	// B5 (cloud client class): wildcard allowlist, no suffix tricks, a
	// redirect to the metadata endpoint refused, and RefusePrivate turning
	// an RFC1918 answer into E_ENDPOINT_PRIVATE before any dial.
	res := &fakeResolver{hosts: map[string][]string{
		"sts.amazonaws.com":                  {"52.1.2.3"},
		"evil.amazonaws.com.attacker.net":    {"52.1.2.4"},
		"vpce-1.sts.eu-west-1.amazonaws.com": {"10.20.30.40"},
	}}
	cloud, err := NewEndpointClientPolicy([]string{"*.amazonaws.com"}, HTTPOptions{}, EndpointPolicy{RefusePrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	d := cloud.Transport.(*limitedTransport).dialer
	d.Resolver = res
	ctx := context.Background()
	if err := d.CheckURL(ctx, mustURL(t, "https://sts.amazonaws.com/")); err != nil {
		t.Fatalf("public AWS endpoint refused: %v", err)
	}
	if err := d.CheckURL(ctx, mustURL(t, "https://evil.amazonaws.com.attacker.net/")); err == nil || !strings.Contains(err.Error(), CodeScopeNotAllowed) {
		t.Fatalf("suffix trick accepted: %v", err)
	}
	if err := d.CheckURL(ctx, mustURL(t, "http://169.254.169.254/latest/meta-data/")); err == nil || !strings.Contains(err.Error(), "E_SCOPE") {
		t.Fatalf("metadata endpoint accepted: %v", err)
	}
	if err := d.CheckURL(ctx, mustURL(t, "https://vpce-1.sts.eu-west-1.amazonaws.com/")); err == nil || !strings.Contains(err.Error(), CodeEndpointPrivate) {
		t.Fatalf("private (PrivateLink) endpoint accepted: %v", err)
	}
	// A redirect from an allowed host to the metadata endpoint is refused
	// by the redirect policy (the same check), never followed.
	if err := cloud.CheckRedirect(&http.Request{URL: mustURL(t, "http://169.254.169.254/")}, []*http.Request{{URL: mustURL(t, "https://sts.amazonaws.com/")}}); err == nil {
		t.Fatal("redirect to metadata followed")
	} else if _, ok := AsRedirectOutOfScope(err); !ok {
		t.Fatalf("redirect refusal type: %v", err)
	}
	// Without RefusePrivate (test override) the private answer is allowed
	// when the host is explicitly listed; with AllowMetadata the built-in
	// deny is set aside for that one client only.
	plain, _ := NewEndpointClientPolicy([]string{"vpce-1.sts.eu-west-1.amazonaws.com"}, HTTPOptions{}, EndpointPolicy{})
	pd := plain.Transport.(*limitedTransport).dialer
	pd.Resolver = res
	if err := pd.CheckURL(ctx, mustURL(t, "https://vpce-1.sts.eu-west-1.amazonaws.com/")); err != nil {
		t.Fatalf("listed private host without RefusePrivate: %v", err)
	}
	meta, _ := NewEndpointClientPolicy([]string{"169.254.169.254"}, HTTPOptions{}, EndpointPolicy{AllowMetadata: true})
	if err := meta.Transport.(*limitedTransport).dialer.CheckURL(ctx, mustURL(t, "http://169.254.169.254/latest/api/token")); err != nil {
		t.Fatalf("AllowMetadata client refused IMDS: %v", err)
	}
	if err := meta.Transport.(*limitedTransport).dialer.CheckURL(ctx, mustURL(t, "http://169.254.170.2/v2/credentials")); err == nil {
		t.Fatal("AllowMetadata client reached an unlisted metadata host")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}

// TestNoRawDialers walks every non-test Go file under internal/ and fails
// on anything that could open an outbound connection without going through
// safety.Dialer or a client built here (SAFETY.md item 9): raw net dialers,
// the default HTTP client/transport and the package-level helpers that use
// them, composite literals, new() and value-typed variables/fields of
// net.Dialer or http.Transport (a zero value is a working default dialer),
// any http.Client literal outside internal/safety, an http.Client literal
// without a Transport inside it, and dot-imports of net or net/http (which
// would hide every one of these from the selector checks). Import aliases
// are resolved, so `import h "net/http"` does not evade the test.
func TestNoRawDialers(t *testing.T) {
	const safetyDir = "internal/safety"
	forbiddenFuncs := map[string]bool{
		"net.Dial": true, "net.DialTimeout": true, "net.DialIP": true, "net.DialTCP": true, "net.DialUDP": true, "net.DialUnix": true,
		"net/http.DefaultClient": true, "net/http.Get": true, "net/http.Post": true, "net/http.Head": true, "net/http.PostForm": true,
		"net/http.DefaultTransport": true,
	}
	// Types whose zero value or literal is a usable dialer/transport.
	rawTypes := map[string]bool{"net.Dialer": true, "net/http.Transport": true}
	const clientType = "net/http.Client"
	root := filepath.Join("..", "..", "internal")
	var files []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if len(files) < 20 {
		t.Fatalf("expected sources under internal/, found %d", len(files))
	}
	fset := token.NewFileSet()
	var violations []string
	for _, f := range files {
		rel, _ := filepath.Rel(filepath.Join("..", ".."), f)
		rel = filepath.ToSlash(rel)
		inSafety := filepath.ToSlash(filepath.Dir(rel)) == safetyDir
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		report := func(n ast.Node, what string) {
			violations = append(violations, fmt.Sprintf("%s:%d: %s", rel, fset.Position(n.Pos()).Line, what))
		}
		// Local import name -> import path, for net and net/http only.
		imports := map[string]string{}
		for _, im := range node.Imports {
			path := strings.Trim(im.Path.Value, `"`)
			if path != "net" && path != "net/http" {
				continue
			}
			name := path[strings.LastIndex(path, "/")+1:]
			if im.Name != nil {
				name = im.Name.Name
			}
			switch name {
			case ".":
				report(im, "dot-import of "+path)
				continue
			case "_":
				continue
			}
			imports[name] = path
		}
		if len(imports) == 0 {
			continue
		}
		// qualified returns "<import path>.<Sel>" for a selector on one of
		// the tracked imports.
		qualified := func(e ast.Expr) (string, bool) {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return "", false
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			path, ok := imports[id.Name]
			if !ok {
				return "", false
			}
			return path + "." + sel.Sel.Name, true
		}
		checkValueType := func(n ast.Node, typ ast.Expr, what string) {
			if q, ok := qualified(typ); ok && rawTypes[q] && !inSafety {
				report(n, what+" of type "+q)
			}
		}
		ast.Inspect(node, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if q, ok := qualified(x); ok && forbiddenFuncs[q] && !inSafety {
					report(x, q)
				}
			case *ast.CompositeLit:
				q, ok := qualified(x.Type)
				if !ok {
					return true
				}
				switch {
				case rawTypes[q] && !inSafety:
					report(x, q+"{} literal")
				case q == clientType && !inSafety:
					report(x, q+"{} literal outside "+safetyDir)
				case q == clientType:
					hasTransport := false
					for _, el := range x.Elts {
						if kv, ok := el.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Transport" {
								hasTransport = true
							}
						}
					}
					if !hasTransport {
						report(x, q+"{} literal without a Transport (would use http.DefaultTransport)")
					}
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
					if q, ok := qualified(x.Args[0]); ok && (rawTypes[q] || q == clientType) && !inSafety {
						report(x, "new("+q+")")
					}
				}
			case *ast.ValueSpec:
				if x.Type != nil {
					checkValueType(x, x.Type, "var")
				}
			case *ast.Field:
				checkValueType(x, x.Type, "field")
			case *ast.TypeSpec:
				checkValueType(x, x.Type, "type")
			}
			return true
		})
	}
	if len(violations) > 0 {
		t.Fatalf("raw dialers or default HTTP clients:\n  %s", strings.Join(violations, "\n  "))
	}
}
