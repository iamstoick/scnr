package sca

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"
)

// Package is one dependency found in a lockfile, manifest or OS package
// database.
type Package struct {
	// Ecosystem is the OSV ecosystem name: Go | npm | PyPI | RubyGems |
	// crates.io | Packagist | Maven | Alpine:v3.18 | Debian:12 | Ubuntu:22.04.
	Ecosystem string
	Name      string
	Version   string
	Direct    bool
	File      string
	Line      int
	// Source is the OS source package (apk origin, dpkg Source) when it
	// differs from Name; OSV advisories for Alpine/Debian/Ubuntu are keyed by
	// it. The PURL keeps the binary package name like trivy and grype do.
	Source string
}

// QueryName is the name OSV is asked about.
func (p Package) QueryName() string {
	if p.Source != "" {
		return p.Source
	}
	return p.Name
}

// purlType maps an OSV ecosystem to its package-url type and namespace.
func purlType(ecosystem string) (typ, namespace string) {
	switch {
	case ecosystem == "Go":
		return "golang", ""
	case ecosystem == "npm":
		return "npm", ""
	case ecosystem == "PyPI":
		return "pypi", ""
	case ecosystem == "RubyGems":
		return "gem", ""
	case ecosystem == "crates.io":
		return "cargo", ""
	case ecosystem == "Packagist":
		return "composer", ""
	case ecosystem == "Maven":
		return "maven", ""
	case strings.HasPrefix(ecosystem, "Alpine"):
		return "apk", "alpine"
	case strings.HasPrefix(ecosystem, "Debian"):
		return "deb", "debian"
	case strings.HasPrefix(ecosystem, "Ubuntu"):
		return "deb", "ubuntu"
	}
	return strings.ToLower(ecosystem), ""
}

// PURL returns the package URL for the package without qualifiers, which is
// the shared SCA scheme (Section 5.6): native, trivy and grype findings for
// the same vulnerability in the same package collapse onto one fingerprint.
func (p Package) PURL() string {
	typ, ns := purlType(p.Ecosystem)
	name := p.Name
	switch typ {
	case "golang", "composer":
		if i := strings.LastIndex(name, "/"); i > 0 {
			ns, name = name[:i], name[i+1:]
		}
	case "npm":
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				ns, name = name[:i], name[i+1:]
			}
		}
	case "pypi":
		name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	case "maven":
		if i := strings.Index(name, ":"); i > 0 {
			ns, name = name[:i], name[i+1:]
		}
	}
	return packageurl.NewPackageURL(typ, ns, name, p.Version, nil, "").ToString()
}

// NormalizePURL parses a package URL produced by another tool and returns it
// in the shared scheme: qualifiers (arch, distro, upstream, ...) and subpath
// dropped, components percent-encoded the same way PURL does. ok is false
// for anything that does not parse as a PURL.
func NormalizePURL(s string) (string, bool) {
	if len(s) > 1024 {
		return "", false
	}
	p, err := packageurl.FromString(s)
	if err != nil || p.Type == "" || p.Name == "" {
		return "", false
	}
	p.Qualifiers = nil
	p.Subpath = ""
	return p.ToString(), true
}

// MaxLockfileBytes caps parsed lockfiles.
const MaxLockfileBytes = 20 << 20

// Parser parses one lockfile format.
type Parser struct {
	// Match reports whether the basename is handled.
	Match func(base string) bool
	Parse func(file string, content []byte) ([]Package, error)
}

func exact(names ...string) func(string) bool {
	return func(b string) bool {
		for _, n := range names {
			if b == n {
				return true
			}
		}
		return false
	}
}

// Parsers for every supported lockfile/manifest (Phase 1 + Phase 3).
var Parsers = []Parser{
	{Match: exact("go.mod"), Parse: ParseGoMod},
	{Match: exact("package-lock.json"), Parse: ParsePackageLock},
	{Match: func(b string) bool {
		return b == "requirements.txt" || strings.HasSuffix(b, "-requirements.txt") || strings.HasPrefix(b, "requirements-") && strings.HasSuffix(b, ".txt")
	}, Parse: ParseRequirements},
	{Match: exact("yarn.lock"), Parse: ParseYarnLock},
	{Match: exact("pnpm-lock.yaml"), Parse: ParsePnpmLock},
	{Match: exact("poetry.lock"), Parse: ParsePoetryLock},
	{Match: exact("Pipfile.lock"), Parse: ParsePipfileLock},
	{Match: exact("Gemfile.lock"), Parse: ParseGemfileLock},
	{Match: exact("Cargo.lock"), Parse: ParseCargoLock},
	{Match: exact("composer.lock"), Parse: ParseComposerLock},
	{Match: exact("pom.xml"), Parse: ParsePomXML},
}

// ParserFor returns the parser for a file basename.
func ParserFor(base string) (Parser, bool) {
	for _, p := range Parsers {
		if p.Match(base) {
			return p, true
		}
	}
	return Parser{}, false
}

// lines iterates content line by line (lines over 1 MiB fail the scan).
func lines(content []byte, fn func(n int, l string)) error {
	sc := bufio.NewScanner(bytes.NewReader(content))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		fn(n, sc.Text())
	}
	return sc.Err()
}

var goReqRe = regexp.MustCompile(`^\s*([^\s]+)\s+(v[0-9][^\s]*)\s*(//.*)?$`)

// ParseGoMod extracts require entries (direct and indirect).
func ParseGoMod(file string, content []byte) ([]Package, error) {
	var d Dedupe
	inBlock := false
	err := lines(content, func(line int, l string) {
		l = strings.TrimSpace(l)
		switch {
		case l == "require (":
			inBlock = true
			return
		case inBlock && l == ")":
			inBlock = false
			return
		case strings.HasPrefix(l, "require "):
			l = strings.TrimPrefix(l, "require ")
		case !inBlock:
			return
		}
		m := goReqRe.FindStringSubmatch(l)
		if m == nil {
			return
		}
		d.Add(Package{Ecosystem: "Go", Name: m[1], Version: m[2], Direct: !strings.Contains(m[3], "indirect"), File: file, Line: line})
	})
	return d.out, err
}

type packageLock struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`
	Dependencies    map[string]packageLockDep   `json:"dependencies"` // v1 fallback
}

type packageLockEntry struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
}

type packageLockDep struct {
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
}

// ParsePackageLock handles lockfileVersion 2 and 3 (and v1 "dependencies"
// as a best-effort fallback). Only known fields are read.
func ParsePackageLock(file string, content []byte) ([]Package, error) {
	var pl packageLock
	if err := json.Unmarshal(content, &pl); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	var d Dedupe
	add := func(name, version string, direct bool) {
		d.Add(Package{Ecosystem: "npm", Name: name, Version: version, Direct: direct, File: file})
	}
	for path, e := range pl.Packages {
		if path == "" || e.Link {
			continue
		}
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 {
			continue
		}
		name := path[i+len("node_modules/"):]
		direct := !strings.Contains(path[:i], "node_modules/")
		add(name, e.Version, direct)
	}
	if len(pl.Packages) == 0 {
		for name, dep := range pl.Dependencies {
			add(name, dep.Version, true)
		}
	}
	return d.out, nil
}

var reqPinRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)`)

// ParseRequirements extracts `name==version` pins. Unpinned lines are
// skipped (no version to look up).
func ParseRequirements(file string, content []byte) ([]Package, error) {
	var d Dedupe
	err := lines(content, func(line int, l string) {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "-") {
			return
		}
		if i := strings.Index(l, ";"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		m := reqPinRe.FindStringSubmatch(l)
		if m == nil {
			return
		}
		d.Add(Package{Ecosystem: "PyPI", Name: m[1], Version: m[2], Direct: true, File: file, Line: line})
	})
	return d.out, err
}
