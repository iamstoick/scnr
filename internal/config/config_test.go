package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseStrict(t *testing.T) {
	cfg, err := Parse([]byte("authorization: {acknowledged: true, by: gerald, at: 2026-10-10T09:00:00Z}\nscope:\n  allow: [10.0.0.0/8]\n  deny: [\"*.prod.example.com\"]\nlimits: {rate_per_sec: 200}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Authorization.Acknowledged || cfg.Authorization.By != "gerald" || cfg.Authorization.At.Year() != 2026 || cfg.Limits.RatePerSec != 200 || len(cfg.Scope.Deny) != 1 {
		t.Fatalf("%+v", cfg)
	}
	if _, err := Parse([]byte("scope:\n  allow: []\n  bogus: 1\n")); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := Parse([]byte("limits: {rate_per_sec: -1}\n")); err == nil {
		t.Fatal("negative limit accepted")
	}
	if cfg, err := Parse(nil); err != nil || cfg.Authorization.Acknowledged {
		t.Fatalf("empty config: %+v %v", cfg, err)
	}
	// tools.nuclei_templates: the opt-in for a local nuclei corpus; absolute paths only.
	if cfg, err := Parse([]byte("tools: {nuclei_templates: /opt/nuclei-templates}\n")); err != nil || cfg.Tools.NucleiTemplates != "/opt/nuclei-templates" {
		t.Fatalf("tools.nuclei_templates: %+v %v", cfg, err)
	}
	if _, err := Parse([]byte("tools: {nuclei_templates: relative/dir}\n")); err == nil {
		t.Fatal("relative nuclei_templates accepted")
	}
}

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	_, err := Load(p)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file should be ErrNotExist, got %v", err)
	}
	c := &Config{Authorization: Authorization{Acknowledged: true, By: "x", At: time.Now().UTC().Truncate(time.Second)}, Scope: Scope{Allow: []string{"a"}}}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(p)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("perm %v", info.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil || !got.Authorization.Acknowledged || got.Path != p {
		t.Fatalf("%+v %v", got, err)
	}
	big := make([]byte, MaxConfigBytes+1)
	os.WriteFile(p, big, 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("oversized config accepted")
	}
	if !strings.Contains(Skeleton(Authorization{}), AckText) {
		t.Fatal("skeleton must quote the acknowledgment text")
	}
}

func TestHome(t *testing.T) {
	t.Setenv("SCNR_HOME", "/tmp/scnr-home-test")
	h, _ := Home()
	if h != "/tmp/scnr-home-test" {
		t.Fatal(h)
	}
	t.Setenv("SCNR_HOME", "")
	t.Setenv("CI", "true")
	h, _ = Home()
	if filepath.Base(h) != ".scnr" || !filepath.IsAbs(h) {
		t.Fatal(h)
	}
	t.Setenv("CI", "")
	h, _ = Home()
	uh, _ := os.UserHomeDir()
	if h != filepath.Join(uh, ".scnr") {
		t.Fatal(h)
	}
}
