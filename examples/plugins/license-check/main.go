// Command scnr-plugin-license-check is scnr's example plugin: it flags
// npm packages without a license field and repositories without a
// LICENSE file. It speaks the plugin protocol on stdin/stdout and uses
// only the standard library, so it doubles as the protocol reference
// implementation. Copy it to start your own plugin.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed manifest.json
var manifestSource []byte

type requestTarget struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type request struct {
	Protocol int           `json:"protocol"`
	Target   requestTarget `json:"target"`
	Scratch  string        `json:"scratch"`
	Profile  string        `json:"profile"`
	Deadline string        `json:"deadline"`
	Broker   string        `json:"broker"`
}

type finding struct {
	Rule       string            `json:"rule"`
	Location   string            `json:"location"`
	Confidence string            `json:"confidence"`
	CVEs       []string          `json:"cves,omitempty"`
	References []string          `json:"references,omitempty"`
	Evidence   []findingEvidence `json:"evidence,omitempty"`
}

type findingEvidence struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Text     string `json:"text"`
}

const (
	maxWalkEntries = 50000
	maxFindings    = 5000
	maxPackageJSON = 1 << 20
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "manifest" {
		os.Stdout.Write(manifestSource)
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: scnr-plugin-license-check [manifest|run]")
		os.Exit(2)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "license-check:", err)
		os.Exit(1)
	}
}

func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return err
	}
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("bad request: %w", err)
	}
	if req.Protocol != 1 {
		return fmt.Errorf("protocol %d not supported", req.Protocol)
	}
	if req.Target.Type != "path" {
		return fmt.Errorf("path targets only, got %q", req.Target.Type)
	}
	var deadline time.Time
	if req.Deadline != "" {
		deadline, _ = time.Parse(time.RFC3339, req.Deadline)
	}
	root := req.Target.Value
	out := json.NewEncoder(os.Stdout)
	emitted := 0
	emit := func(f finding) error {
		if emitted >= maxFindings {
			return nil
		}
		emitted++
		return out.Encode(f)
	}
	entries := 0
	expired := func() bool { return !deadline.IsZero() && time.Now().After(deadline) }
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || expired() {
			return err
		}
		entries++
		if entries > maxWalkEntries {
			return filepath.SkipAll
		}
		if d.IsDir() || !strings.EqualFold(d.Name(), "package.json") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		lic, name, ok := packageLicense(path)
		if !ok {
			return nil // unreadable: not our call
		}
		if lic != "" {
			return nil
		}
		return emit(finding{
			Rule: "unlicensed-package", Location: rel, Confidence: "firm",
			Evidence: []findingEvidence{{Kind: "package", Location: rel, Text: "package " + name + " has no license field"}},
		})
	})
	if walkErr != nil {
		return walkErr
	}
	if !expired() && !hasLicenseFile(root) {
		return emit(finding{
			Rule: "missing-license-file", Location: ".", Confidence: "firm",
			Evidence: []findingEvidence{{Kind: "directory", Location: ".", Text: "no LICENSE file at the repository root"}},
		})
	}
	return nil
}

// packageLicense reads name and license from a package.json.
func packageLicense(path string) (license, name string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxPackageJSON+1))
	if err != nil || len(raw) > maxPackageJSON || !json.Valid(raw) {
		return "", "", false
	}
	var doc struct {
		Name    string `json:"name"`
		License any    `json:"license"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return "", "", false
	}
	switch l := doc.License.(type) {
	case string:
		license = l
	case map[string]any:
		license, _ = l["type"].(string)
	}
	if doc.Name == "" {
		doc.Name = filepath.Base(filepath.Dir(path))
	}
	return license, doc.Name, true
}

func hasLicenseFile(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(strings.ToUpper(e.Name()), "LICENSE") {
			return true
		}
	}
	return false
}
