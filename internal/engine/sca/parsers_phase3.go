package sca

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gerald/scnr/internal/engine"
)

// Caps for structured lockfiles. Anything beyond is treated as malformed:
// a lockfile is attacker-controlled input when the repo is not yours.
const (
	// MaxLockEntries caps the packages kept from one lockfile or package
	// database; every parser (lockfiles here, apk/dpkg in engine/image)
	// routes through Dedupe so none can exceed it.
	MaxLockEntries = 200_000
	maxYAMLDepth   = 16
)

// Dedupe keeps the first occurrence of each ecosystem/name/version, drops
// entries without a name or version, and stops at MaxLockEntries.
type Dedupe struct {
	seen map[string]bool
	out  []Package
}

// Packages returns what was kept, in insertion order.
func (d *Dedupe) Packages() []Package { return d.out }

// Add keeps p unless it is incomplete, already seen or over the cap.
func (d *Dedupe) Add(p Package) {
	if p.Name == "" || p.Version == "" || len(d.out) >= MaxLockEntries {
		return
	}
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	k := p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version
	if d.seen[k] {
		return
	}
	d.seen[k] = true
	d.out = append(d.out, p)
}

var (
	yarnHeaderRe  = regexp.MustCompile(`^"?((?:@[^/@"\s]+/)?[^@"\s/]+)@`)
	yarnVersionRe = regexp.MustCompile(`^\s+version:?\s+"?([^"\s]+)"?\s*$`)
)

// ParseYarnLock handles yarn classic (v1) and berry (v2+) lockfiles. Both
// are "header line(s) ending in ':' then indented key/value lines".
func ParseYarnLock(file string, content []byte) ([]Package, error) {
	var d Dedupe
	name, nameLine := "", 0
	err := lines(content, func(line int, l string) {
		if l == "" || strings.HasPrefix(l, "#") {
			return
		}
		if !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":") {
			name, nameLine = "", 0
			first := strings.TrimSpace(strings.SplitN(l, ",", 2)[0])
			if strings.HasPrefix(first, "__metadata") {
				return
			}
			if m := yarnHeaderRe.FindStringSubmatch(first); m != nil {
				name, nameLine = m[1], line
			}
			return
		}
		if name == "" {
			return
		}
		if m := yarnVersionRe.FindStringSubmatch(l); m != nil {
			if strings.HasPrefix(m[1], "0.0.0-use.local") { // berry workspace entry
				return
			}
			d.Add(Package{Ecosystem: "npm", Name: name, Version: m[1], Direct: true, File: file, Line: nameLine})
			name = ""
		}
	})
	return d.out, err
}

// decodeYAMLCapped decodes YAML into out after rejecting documents nested
// deeper than maxYAMLDepth or with more than maxLockEntries nodes. The
// depth is measured on the bytes first (yaml.v3 recurses per level and a
// stack overflow is fatal); yaml.v3 already refuses excessive alias
// expansion and the node walk bounds what the alias limit still lets
// through.
func decodeYAMLCapped(content []byte, out any) error {
	if engine.YAMLDepth(content, maxYAMLDepth) > maxYAMLDepth {
		return errors.New("yaml: document too deep")
	}
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(content))
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	count := 0
	var walk func(n *yaml.Node, depth int) error
	walk = func(n *yaml.Node, depth int) error {
		count++
		if depth > maxYAMLDepth || count > MaxLockEntries {
			return errors.New("yaml: document too deep or too large")
		}
		for _, c := range n.Content {
			if err := walk(c, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(&root, 0); err != nil {
		return err
	}
	return root.Decode(out)
}

// ParsePnpmLock reads the packages map of pnpm-lock.yaml (lockfile v5, v6
// and v9 key shapes).
func ParsePnpmLock(file string, content []byte) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Dev bool `yaml:"dev"`
		} `yaml:"packages"`
	}
	if err := decodeYAMLCapped(content, &lock); err != nil {
		return nil, fmt.Errorf("pnpm-lock.yaml: %w", err)
	}
	var d Dedupe
	for key := range lock.Packages {
		name, version, ok := splitPnpmKey(key)
		if ok {
			d.Add(Package{Ecosystem: "npm", Name: name, Version: version, Direct: true, File: file})
		}
	}
	return d.out, nil
}

// splitPnpmKey turns "/lodash/4.17.20", "/@s/x@1.0.0(peer)" or "lodash@1.0.0"
// into (name, version).
func splitPnpmKey(key string) (string, string, bool) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.IndexAny(k, "(_"); i > 0 {
		k = k[:i]
	}
	if i := strings.LastIndex(k, "@"); i > 0 {
		return k[:i], k[i+1:], k[i+1:] != ""
	}
	if i := strings.LastIndex(k, "/"); i > 0 {
		return k[:i], k[i+1:], k[i+1:] != ""
	}
	return "", "", false
}

var tomlKVRe = regexp.MustCompile(`^(name|version|source)\s*=\s*"([^"]*)"`)

type tomlPackage struct {
	name, version, source string
	line                  int
}

// tomlPackages extracts [[package]] tables with name/version/source from
// poetry.lock and Cargo.lock without a TOML dependency: both files are
// generated with one key per line and double-quoted strings.
func tomlPackages(content []byte) ([]tomlPackage, error) {
	var out []tomlPackage
	var cur *tomlPackage
	err := lines(content, func(line int, l string) {
		l = strings.TrimSpace(l)
		switch {
		case l == "[[package]]":
			out = append(out, tomlPackage{line: line})
			cur = &out[len(out)-1]
		case strings.HasPrefix(l, "["):
			cur = nil
		case cur != nil:
			if m := tomlKVRe.FindStringSubmatch(l); m != nil {
				switch m[1] {
				case "name":
					cur.name = m[2]
				case "version":
					cur.version = m[2]
				case "source":
					cur.source = m[2]
				}
			}
		}
	})
	return out, err
}

// ParsePoetryLock reads poetry.lock [[package]] entries.
func ParsePoetryLock(file string, content []byte) ([]Package, error) {
	pkgs, err := tomlPackages(content)
	var d Dedupe
	for _, p := range pkgs {
		d.Add(Package{Ecosystem: "PyPI", Name: p.name, Version: p.version, Direct: true, File: file, Line: p.line})
	}
	return d.out, err
}

// ParseCargoLock reads Cargo.lock [[package]] entries; workspace crates
// (no source) are local code, not dependencies, and are skipped.
func ParseCargoLock(file string, content []byte) ([]Package, error) {
	pkgs, err := tomlPackages(content)
	var d Dedupe
	for _, p := range pkgs {
		if p.source == "" {
			continue
		}
		d.Add(Package{Ecosystem: "crates.io", Name: p.name, Version: p.version, Direct: true, File: file, Line: p.line})
	}
	return d.out, err
}

// ParsePipfileLock reads the default and develop sections of Pipfile.lock.
func ParsePipfileLock(file string, content []byte) ([]Package, error) {
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("pipfile.lock: %w", err)
	}
	var d Dedupe
	for _, sec := range []map[string]struct {
		Version string `json:"version"`
	}{lock.Default, lock.Develop} {
		for name, e := range sec {
			v := strings.TrimPrefix(e.Version, "==")
			d.Add(Package{Ecosystem: "PyPI", Name: name, Version: v, Direct: true, File: file})
		}
	}
	return d.out, nil
}

var gemSpecRe = regexp.MustCompile(`^    ([A-Za-z0-9_.-]+) \(([^)\s]+)\)\s*$`)

// ParseGemfileLock reads the `specs:` entries of GEM sections (4-space
// indented "name (version)"; dependencies are indented 6 and ignored).
func ParseGemfileLock(file string, content []byte) ([]Package, error) {
	var d Dedupe
	inGem := false
	err := lines(content, func(line int, l string) {
		switch {
		case l == "GEM":
			inGem = true
		case l != "" && !strings.HasPrefix(l, " "):
			inGem = false
		case inGem:
			if m := gemSpecRe.FindStringSubmatch(l); m != nil {
				d.Add(Package{Ecosystem: "RubyGems", Name: m[1], Version: m[2], Direct: true, File: file, Line: line})
			}
		}
	})
	return d.out, err
}

// ParseComposerLock reads packages and packages-dev of composer.lock. A
// leading "v" is dropped from versions to match Packagist advisories.
func ParseComposerLock(file string, content []byte) ([]Package, error) {
	var lock struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}
	var d Dedupe
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		d.Add(Package{Ecosystem: "Packagist", Name: p.Name, Version: strings.TrimPrefix(p.Version, "v"), Direct: true, File: file})
	}
	return d.out, nil
}

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

var pomPropRe = regexp.MustCompile(`^\$\{([A-Za-z0-9_.-]+)\}$`)

// ParsePomXML reads the direct <dependencies> of a pom.xml. Versions that
// reference ${properties} are resolved from <properties>; anything else
// unresolved (parent POMs, dependencyManagement) is skipped. Go's XML
// decoder does not expand external or DTD entities.
func ParsePomXML(file string, content []byte) ([]Package, error) {
	var pom struct {
		Properties struct {
			Any []struct {
				XMLName xml.Name
				Value   string `xml:",chardata"`
			} `xml:",any"`
		} `xml:"properties"`
		Dependencies struct {
			Dependency []struct {
				GroupID    string `xml:"groupId"`
				ArtifactID string `xml:"artifactId"`
				Version    string `xml:"version"`
			} `xml:"dependency"`
		} `xml:"dependencies"`
	}
	dec := xml.NewDecoder(bytes.NewReader(content))
	dec.Strict = true
	if err := dec.Decode(&pom); err != nil {
		return nil, fmt.Errorf("pom.xml: %w", err)
	}
	props := map[string]string{}
	for _, p := range pom.Properties.Any {
		props[p.XMLName.Local] = strings.TrimSpace(p.Value)
	}
	var d Dedupe
	for _, dep := range pom.Dependencies.Dependency {
		v := strings.TrimSpace(dep.Version)
		if m := pomPropRe.FindStringSubmatch(v); m != nil {
			v = props[m[1]]
		}
		if strings.Contains(v, "$") || strings.ContainsAny(v, "[],()") {
			continue // unresolved property or version range
		}
		g, a := strings.TrimSpace(dep.GroupID), strings.TrimSpace(dep.ArtifactID)
		if g == "" || a == "" {
			continue
		}
		d.Add(Package{Ecosystem: "Maven", Name: g + ":" + a, Version: v, Direct: true, File: file})
	}
	return d.out, nil
}
