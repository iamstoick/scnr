// Package report renders a scan from the store. Reporters page findings
// through store.FindingIterator and never need the whole scan in memory
// (HTML caps the rendered list; JSON streams).
package report

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/store"
)

// SchemaVersion of the JSON report (the public contract).
const SchemaVersion = "1"

// Reporter writes one format.
type Reporter interface {
	Name() string
	FileName() string
	Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error
}

// Meta is extra context every reporter may show.
type Meta struct {
	PreviousScore *int   // nil when no previous scan
	ExploitData   bool   // KEV/EPSS tables populated
	Version       string // scnr version
}

// Registry of reporters by name.
func Registry(meta Meta) map[string]Reporter {
	return map[string]Reporter{
		"json":  &JSON{Meta: meta},
		"html":  &HTML{Meta: meta},
		"sarif": &SARIF{Meta: meta},
		"md":    &Markdown{Meta: meta},
		"csv":   &CSV{Meta: meta},
	}
}

// ParseFormats validates a comma list of formats.
func ParseFormats(spec string, available map[string]Reporter) ([]Reporter, error) {
	var out []Reporter
	for _, f := range strings.Split(spec, ",") {
		f = strings.TrimSpace(strings.ToLower(f))
		if f == "" {
			continue
		}
		r, ok := available[f]
		if !ok {
			names := make([]string, 0, len(available))
			for n := range available {
				names = append(names, n)
			}
			sort.Strings(names)
			return nil, fmt.Errorf("unknown format %q (available: %s)", f, strings.Join(names, ","))
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no output formats selected")
	}
	return out, nil
}

// WriteAll renders every reporter into dir and returns the written paths.
func WriteAll(ctx context.Context, s *store.Store, scan domain.Scan, reporters []Reporter, dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	var paths []string
	for _, r := range reporters {
		p := filepath.Join(dir, r.FileName())
		f, err := safety.CreateOutputFile(p)
		if err != nil {
			return paths, err
		}
		err = r.Write(ctx, s.Iterate(scan.ID), scan, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return paths, fmt.Errorf("%s report: %w", r.Name(), err)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// assetsFor derives the assets list from the scan targets plus finding keys.
func assetsFor(scan domain.Scan, extraKeys []string) []domain.Asset {
	seen := map[string]bool{}
	var out []domain.Asset
	for _, t := range scan.Targets {
		k := t.AssetKey()
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, domain.Asset{Key: k, Type: t.Type, Name: t.Value, Public: t.Public, Labels: map[string]string{}})
	}
	for _, k := range extraKeys {
		if seen[k] {
			continue
		}
		seen[k] = true
		typ := domain.TargetHost
		name := k
		if i := strings.Index(k, ":"); i > 0 {
			name = k[i+1:]
		}
		out = append(out, domain.Asset{Key: k, Type: typ, Name: name, Labels: map[string]string{}})
	}
	return out
}
