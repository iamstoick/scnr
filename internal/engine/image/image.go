// Package image scans container images for apk/dpkg OS packages and
// lockfiles and looks them up in OSV through the sca engine. Only local
// archives are read: a `docker save` tarball or an OCI image layout
// directory. Registry and daemon pulls would bypass the safety dialer, so
// they are not implemented; a bare image reference is reported as skipped
// with the `docker save` command to run instead.
package image

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/engine/sca"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "image"

// Label on image targets that names the local source; targets without it
// are registry references, which this engine does not pull.
const (
	SourceLabel      = "source"
	SourceDockerTar  = "docker-archive"
	SourceOCILayout  = "oci-layout"
	skipRegistryHint = "scnr scans local image archives only: run `docker save %s -o image.tar` (or `skopeo copy docker://%s oci:dir`) and scan that file; trivy/grype adapters are limited the same way"
)

// Engine implements engine.Engine.
type Engine struct {
	rules  engine.RuleSet
	sca    *sca.Engine
	Limits Limits
}

// New builds the engine; the sca engine provides OSV lookup and rule prose.
func New(s *sca.Engine) (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rs, sca: s, Limits: DefaultLimits}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Supports image targets.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetImage }

// IsLocal reports whether the image target names a local archive.
func IsLocal(t domain.Target) bool {
	s := t.Labels[SourceLabel]
	return s == SourceDockerTar || s == SourceOCILayout
}

// SkipRegistry is the SkipError for a registry reference.
func SkipRegistry(t domain.Target) error {
	return &engine.SkipError{Reason: fmt.Sprintf(skipRegistryHint, t.Value, t.Value)}
}

// Inventory is what Collect found in an image.
type Inventory struct {
	OS       OS
	Packages []sca.Package // OS packages (ecosystem set when known) then lockfile packages
	OSPkgs   int
	Contents *Contents
}

// Collect opens the archive and parses OS databases and lockfiles.
func (e *Engine) Collect(p string) (*Inventory, error) {
	c, err := Open(p, e.Limits)
	if err != nil {
		return nil, err
	}
	inv := &Inventory{Contents: c}
	if b, ok := c.Files[osRelease]; ok {
		inv.OS = parseOSRelease(b)
	} else if b, ok := c.Files[usrOSRelease]; ok {
		inv.OS = parseOSRelease(b)
	}
	eco := inv.OS.Ecosystem()
	if b, ok := c.Files[apkDB]; ok {
		inv.Packages = append(inv.Packages, parseAPK(b, eco, apkDB)...)
	}
	if b, ok := c.Files[dpkgStatus]; ok {
		inv.Packages = append(inv.Packages, parseDpkg(b, eco, dpkgStatus)...)
	}
	var statusD []string
	for p := range c.Files {
		if strings.HasPrefix(p, dpkgStatusD) {
			statusD = append(statusD, p)
		}
	}
	sort.Strings(statusD)
	for _, p := range statusD {
		inv.Packages = append(inv.Packages, parseDpkg(c.Files[p], eco, dpkgStatus)...)
	}
	inv.OSPkgs = len(inv.Packages)
	var locks []string
	for p := range c.Files {
		if _, ok := sca.ParserFor(path.Base(p)); ok {
			locks = append(locks, p)
		}
	}
	sort.Strings(locks)
	for _, p := range locks {
		parser, _ := sca.ParserFor(path.Base(p))
		got, err := parser.Parse(p, c.Files[p])
		if err != nil {
			continue // malformed lockfile inside the image: skipped, not fatal
		}
		inv.Packages = append(inv.Packages, got...)
	}
	return inv, nil
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	if !IsLocal(t) {
		return engine.Plan{Summary: "registry reference: will be skipped (" + fmt.Sprintf(skipRegistryHint, t.Value, t.Value) + ")"}, nil
	}
	inv, err := e.Collect(t.Value)
	if err != nil {
		return engine.Plan{Summary: "image archive could not be read: " + err.Error()}, nil
	}
	p := engine.Plan{Summary: fmt.Sprintf("%d layers, %s, %d OS packages, %d lockfile packages", inv.Contents.Layers, osLabel(inv.OS), inv.OSPkgs, len(inv.Packages)-inv.OSPkgs), Network: o.Online}
	if o.Online {
		p.Summary += "; package names and versions will be sent to api.osv.dev"
		p.EstDuration = 15 * time.Second
	}
	return p, nil
}

func osLabel(o OS) string {
	if o.Name != "" {
		return o.Name
	}
	if o.ID == "" {
		return "unknown OS"
	}
	return o.ID + " " + o.VersionID
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	if !IsLocal(t) {
		return SkipRegistry(t)
	}
	assetKey := t.AssetKey()
	inv, err := e.Collect(t.Value)
	switch {
	case errors.Is(err, ErrTooLarge):
		return emit(e.rules.NewFinding("image.too-large", assetKey, t.Value, domain.Confirmed))
	case errors.Is(err, ErrUnsupportedLayer):
		return emit(e.rules.NewFinding("image.unsupported-layer", assetKey, t.Value, domain.Confirmed))
	case err != nil:
		return err
	}
	if inv.Contents.Hostile > 0 {
		f := e.rules.NewFinding("image.hostile-archive", assetKey, t.Value, domain.Confirmed)
		f.Evidence = []domain.Evidence{{Kind: "file", Location: t.Value, Redacted: fmt.Sprintf("%d entries with absolute, traversal or over-long names (or whiteouts past the per-layer cap) were ignored", inv.Contents.Hostile), Hash: domain.SHA256Hex(t.Value)}}
		if err := emit(f); err != nil {
			return err
		}
	}
	if inv.Contents.RPM {
		if err := emit(e.rules.NewFinding("image.rpm-database-found", assetKey, t.Value, domain.Confirmed)); err != nil {
			return err
		}
	}
	lookup := inv.Packages
	if inv.OSPkgs > 0 && inv.OS.Ecosystem() == "" {
		f := e.rules.NewFinding("image.os-unknown", assetKey, t.Value, domain.Firm)
		f.Evidence = []domain.Evidence{{Kind: "file", Location: osRelease, Redacted: fmt.Sprintf("%d OS packages found; os-release: %s", inv.OSPkgs, osLabel(inv.OS)), Hash: domain.SHA256Hex(osLabel(inv.OS))}}
		if err := emit(f); err != nil {
			return err
		}
		lookup = inv.Packages[inv.OSPkgs:]
	}
	return e.sca.Lookup(ctx, lookup, assetKey, Name, o, emit)
}
