// Package sbom writes a CycloneDX 1.5 JSON bill of materials from the same
// package inventory the sca and image engines use. Output goes through the
// cyclonedx-go encoder (encoding/json underneath); every string is control-
// stripped and redacted first because lockfiles and image contents are
// untrusted input that must not inject into the document.
package sbom

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/safety"
)

// Format names accepted by --format.
const FormatCycloneDXJSON = "cyclonedx-json"

// MaxComponents bounds a BOM (an image or monorepo with more is truncated
// and the truncation recorded as a property).
const MaxComponents = 50_000

// Inventory is the input to Write.
type Inventory struct {
	Target   domain.Target
	Packages []sca.Package
	OS       *image.OS // for image targets, when known
	Files    int       // lockfiles parsed (path targets)
	Layers   int       // image layers (image targets)
}

// Collect gathers the inventory for a path or local image target.
func Collect(ctx context.Context, t domain.Target, img *image.Engine) (*Inventory, error) {
	inv := &Inventory{Target: t}
	switch t.Type {
	case domain.TargetPath:
		pkgs, files, err := sca.Collect(ctx, t.Value)
		if err != nil {
			return nil, err
		}
		inv.Packages, inv.Files = pkgs, len(files)
	case domain.TargetImage:
		if !image.IsLocal(t) {
			return nil, fmt.Errorf("sbom: %v", image.SkipRegistry(t))
		}
		got, err := img.Collect(t.Value)
		if err != nil {
			return nil, err
		}
		inv.Packages, inv.Layers = got.Packages, got.Contents.Layers
		if got.OS.ID != "" {
			os := got.OS
			inv.OS = &os
		}
	default:
		return nil, fmt.Errorf("sbom: target type %s is not supported (path or local image archive)", t.Type)
	}
	return inv, nil
}

// Write encodes the inventory as CycloneDX 1.5 JSON. version is the scnr
// version recorded in metadata.tools.
func Write(w io.Writer, inv *Inventory, version string, now time.Time) error {
	red := safety.NewRedactor()
	clean := red.Clean
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuidFromID(domain.NewID())
	bom.Metadata = &cdx.Metadata{
		Timestamp: now.UTC().Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &[]cdx.Component{{Type: cdx.ComponentTypeApplication, Name: "scnr", Version: clean(version, 64)}}},
		Component: subject(inv, clean),
	}
	// Clean before anything (including the PURL) is derived from a package:
	// lockfile and image contents are untrusted.
	pkgs := make([]sca.Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		p.Name, p.Version, p.Ecosystem = clean(p.Name, 256), clean(p.Version, 128), clean(p.Ecosystem, 64)
		if p.Name == "" || p.Version == "" {
			continue
		}
		pkgs = append(pkgs, p)
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Ecosystem != pkgs[j].Ecosystem {
			return pkgs[i].Ecosystem < pkgs[j].Ecosystem
		}
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	comps := make([]cdx.Component, 0, len(pkgs))
	seen := map[string]bool{}
	truncated := 0
	for _, p := range pkgs {
		purl := p.PURL()
		if seen[purl] {
			continue
		}
		seen[purl] = true
		if len(comps) >= MaxComponents {
			truncated++
			continue
		}
		c := cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: purl,
		}
		if ns := purlNamespace(p); ns != "" {
			c.Group = ns
		}
		props := []cdx.Property{{Name: "scnr:ecosystem", Value: p.Ecosystem}}
		if p.File != "" {
			props = append(props, cdx.Property{Name: "scnr:source", Value: clean(p.File, 512)})
		}
		if p.Source != "" {
			props = append(props, cdx.Property{Name: "scnr:upstream", Value: clean(p.Source, 256)})
		}
		c.Properties = &props
		comps = append(comps, c)
	}
	if truncated > 0 {
		bom.Metadata.Properties = &[]cdx.Property{{Name: "scnr:truncated", Value: fmt.Sprintf("%d components omitted beyond the %d cap", truncated, MaxComponents)}}
	}
	bom.Components = &comps
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.EncodeVersion(bom, cdx.SpecVersion1_5)
}

// subject describes what the BOM is about.
func subject(inv *Inventory, clean func(string, int) string) *cdx.Component {
	c := &cdx.Component{Name: clean(inv.Target.Value, 512), BOMRef: "scnr:" + clean(inv.Target.AssetKey(), 600)}
	switch inv.Target.Type {
	case domain.TargetImage:
		c.Type = cdx.ComponentTypeContainer
		if inv.OS != nil {
			props := []cdx.Property{{Name: "scnr:os", Value: clean(inv.OS.ID+" "+inv.OS.VersionID, 128)}, {Name: "scnr:layers", Value: fmt.Sprint(inv.Layers)}}
			c.Properties = &props
		}
	default:
		c.Type = cdx.ComponentTypeApplication
		props := []cdx.Property{{Name: "scnr:lockfiles", Value: fmt.Sprint(inv.Files)}}
		c.Properties = &props
	}
	return c
}

// purlNamespace returns the group/namespace part for ecosystems that have
// one (Maven groupId, npm scope, Composer vendor, Go module path).
func purlNamespace(p sca.Package) string {
	switch p.Ecosystem {
	case "Maven":
		if g, _, ok := strings.Cut(p.Name, ":"); ok {
			return g
		}
	case "npm":
		if strings.HasPrefix(p.Name, "@") {
			if s, _, ok := strings.Cut(p.Name, "/"); ok {
				return s
			}
		}
	case "Packagist", "Go":
		if i := strings.LastIndex(p.Name, "/"); i > 0 {
			return p.Name[:i]
		}
	}
	return ""
}

// uuidFromID formats 32 hex chars as an RFC 4122 v4-shaped UUID (the
// schema's serialNumber pattern requires the dashed form).
func uuidFromID(hex32 string) string {
	b := []byte(hex32)
	b[12] = '4'
	b[16] = "89ab"[int(b[16]-'0')%4]
	return fmt.Sprintf("%s-%s-%s-%s-%s", b[0:8], b[8:12], b[12:16], b[16:20], b[20:32])
}
