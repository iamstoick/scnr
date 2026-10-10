package sca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../../testdata/phase3-repo", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func byName(pkgs []Package) map[string]Package {
	m := map[string]Package{}
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}

// Acceptance 3.1: each new parser has a fixture.
func TestPhase3Parsers(t *testing.T) {
	cases := []struct {
		file, eco, name, version, purl string
		count                          int
	}{
		{"yarn.lock", "npm", "@babel/code-frame", "7.10.4", "pkg:npm/%40babel/code-frame@7.10.4", 2},
		{"pnpm-lock.yaml", "npm", "follow-redirects", "1.15.6", "pkg:npm/follow-redirects@1.15.6", 2},
		{"poetry.lock", "PyPI", "pyyaml", "5.3.1", "pkg:pypi/pyyaml@5.3.1", 2},
		{"Pipfile.lock", "PyPI", "jinja2", "2.11.2", "pkg:pypi/jinja2@2.11.2", 2},
		{"Gemfile.lock", "RubyGems", "nokogiri", "1.13.0", "pkg:gem/nokogiri@1.13.0", 3},
		{"Cargo.lock", "crates.io", "openssl", "0.10.55", "pkg:cargo/openssl@0.10.55", 2},
		{"composer.lock", "Packagist", "symfony/http-kernel", "5.4.20", "pkg:composer/symfony/http-kernel@5.4.20", 3},
		{"pom.xml", "Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", 2},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			p, ok := ParserFor(c.file)
			if !ok {
				t.Fatal("no parser")
			}
			pkgs, err := p.Parse(c.file, fixture(t, c.file))
			if err != nil {
				t.Fatal(err)
			}
			if len(pkgs) != c.count {
				t.Fatalf("got %d packages: %+v", len(pkgs), pkgs)
			}
			got := byName(pkgs)[c.name]
			if got.Ecosystem != c.eco || got.Version != c.version || got.File != c.file {
				t.Fatalf("%+v", got)
			}
			if got.PURL() != c.purl {
				t.Fatalf("purl %s, want %s", got.PURL(), c.purl)
			}
		})
	}
	// Workspace crate (no source) and unresolved pom property are skipped.
	cargo, _ := ParseCargoLock("Cargo.lock", fixture(t, "Cargo.lock"))
	if _, ok := byName(cargo)["demo"]; ok {
		t.Fatal("workspace crate must be skipped")
	}
	pom, _ := ParsePomXML("pom.xml", fixture(t, "pom.xml"))
	if _, ok := byName(pom)["org.unresolved:skipme"]; ok {
		t.Fatal("unresolved property version must be skipped")
	}
	// Collect over the fixture repo sees every ecosystem.
	pkgs, files, err := Collect(t.Context(), "../../../testdata/phase3-repo")
	if err != nil {
		t.Fatal(err)
	}
	ecos := map[string]bool{}
	for _, p := range pkgs {
		ecos[p.Ecosystem] = true
	}
	for _, e := range []string{"Go", "npm", "PyPI", "RubyGems", "crates.io", "Packagist", "Maven"} {
		if !ecos[e] {
			t.Errorf("ecosystem %s missing from %v (files %v)", e, ecos, files)
		}
	}
	if len(files) != 11 {
		t.Fatalf("files %v", files)
	}
}

func TestYarnBerryAndPnpmKeys(t *testing.T) {
	berry := "__metadata:\n  version: 6\n\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n\n\"demo@workspace:.\":\n  version: 0.0.0-use.local\n"
	pkgs, err := ParseYarnLock("yarn.lock", []byte(berry))
	if err != nil || len(pkgs) != 1 || pkgs[0].Name != "left-pad" || pkgs[0].Version != "1.3.0" || pkgs[0].Line != 4 {
		t.Fatalf("%+v %v", pkgs, err)
	}
	for key, want := range map[string][2]string{
		"/lodash/4.17.20": {"lodash", "4.17.20"}, "/@scope/x/1.0.0_react@17": {"@scope/x", "1.0.0"}, "/@scope/x@1.0.0(peer@2)": {"@scope/x", "1.0.0"}, "lodash@4.17.20": {"lodash", "4.17.20"}, "garbage": {"", ""},
	} {
		n, v, _ := splitPnpmKey(key)
		if n != want[0] || v != want[1] {
			t.Errorf("%s -> %s %s", key, n, v)
		}
	}
}

func TestNormalizePURL(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:apk/alpine/musl@1.2.4-r1?arch=x86_64&distro=3.18.4":                      "pkg:apk/alpine/musl@1.2.4-r1",
		"pkg:apk/alpine/musl@1.2.4-r1?arch=x86_64&distro=alpine-3.18.4&upstream=musl": "pkg:apk/alpine/musl@1.2.4-r1",
		"pkg:npm/%40scope/b@1.0.0":                        "pkg:npm/%40scope/b@1.0.0",
		"pkg:deb/debian/libc6@2.36-9?arch=amd64#sub/path": "pkg:deb/debian/libc6@2.36-9",
	} {
		got, ok := NormalizePURL(in)
		if !ok || got != want {
			t.Errorf("%s -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "not a purl", "pkg:", strings.Repeat("pkg:npm/a@", 200)} {
		if _, ok := NormalizePURL(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	// OS packages: PURL keeps the binary name, OSV is asked about the source.
	p := Package{Ecosystem: "Alpine:v3.18", Name: "libcrypto3", Version: "3.1.4-r1", Source: "openssl"}
	if p.PURL() != "pkg:apk/alpine/libcrypto3@3.1.4-r1" || p.QueryName() != "openssl" {
		t.Fatalf("%s %s", p.PURL(), p.QueryName())
	}
	if (Package{Ecosystem: "Debian:12", Name: "libc6", Version: "2.36-9"}).PURL() != "pkg:deb/debian/libc6@2.36-9" {
		t.Fatal("deb purl")
	}
}

// Acceptance 3.1: a YAML alias bomb in pnpm-lock.yaml is refused, not expanded.
func TestPnpmLockAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("a: &a [x, x, x, x, x, x, x, x, x, x]\n")
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		b.WriteString(n + ": &" + n + " [*" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + "]\n")
		prev = n
	}
	// The bomb is referenced from the decoded map so expansion would happen;
	// yaml.v3's alias-ratio limit and our node cap must stop it quickly.
	b.WriteString("packages:\n  /lodash/4.17.20: *" + prev + "\n")
	start := time.Now()
	_, err := ParsePnpmLock("pnpm-lock.yaml", []byte(b.String()))
	if err == nil {
		t.Fatal("alias bomb accepted")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("alias bomb took %s", time.Since(start))
	}
	deep := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	if _, err := ParsePnpmLock("pnpm-lock.yaml", []byte("packages: "+deep+"\n")); err == nil {
		t.Fatal("deep nesting accepted")
	}
}

func FuzzPhase3Parsers(f *testing.F) {
	for _, name := range []string{"yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "Gemfile.lock", "Cargo.lock", "composer.lock", "pom.xml"} {
		if b, err := os.ReadFile(filepath.Join("../../../testdata/phase3-repo", name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("packages: " + strings.Repeat("[", 300) + strings.Repeat("]", 300) + "\n"))
	f.Add([]byte("packages:\n  " + strings.Repeat("- ", 300) + "x\n"))
	f.Add([]byte("<project><dependencies><dependency><groupId>a</groupId></dependency></dependencies></project>"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range Parsers {
			_, _ = p.Parse("f", b) // must never panic
		}
	})
}
