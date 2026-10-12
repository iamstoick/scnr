package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// LockFileName is the tamper-evident record of installed plugins.
const LockFileName = "plugins.lock"

// PluginsDirName holds one directory per installed name@version.
const PluginsDirName = "plugins"

// LockEntry pins one installed version. Capabilities mirror the manifest
// so any change breaks the manifest hash at load.
type LockEntry struct {
	Name           string           `yaml:"name"`
	Version        string           `yaml:"version"`
	BinarySHA256   string           `yaml:"binary_sha256"`
	ManifestSHA256 string           `yaml:"manifest_sha256"`
	PublisherKey   string           `yaml:"publisher_key"`
	Capabilities   LockCapabilities `yaml:"capabilities"`
	InstalledAt    time.Time        `yaml:"installed_at"`
	InstalledBy    string           `yaml:"installed_by"`
}

// LockCapabilities mirrors the manifest capabilities.
type LockCapabilities struct {
	Network string `yaml:"network"`
}

// Lock is the decoded lock file.
type Lock struct {
	Plugins []LockEntry `yaml:"plugins"`
}

// Dir returns the install directory for a name@version.
func Dir(home, name, version string) string {
	return filepath.Join(home, PluginsDirName, name, version)
}

// BinaryPath returns the installed binary path for a lock entry.
func BinaryPath(home string, e LockEntry) string {
	return filepath.Join(Dir(home, e.Name, e.Version), BinaryName(e.Name))
}

// ManifestPath returns the installed manifest path for a lock entry.
func ManifestPath(home string, e LockEntry) string {
	return filepath.Join(Dir(home, e.Name, e.Version), "manifest.json")
}

// LoadLock decodes the lock file. A missing file means no plugins and is
// not an error. A malformed file is: the lock is a trust anchor, so a
// broken one fails loudly rather than scanning with an unknown set.
func LoadLock(home string) (*Lock, error) {
	b, err := os.ReadFile(filepath.Join(home, LockFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Lock{}, nil
		}
		return nil, err
	}
	var l Lock
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("%s: %w", LockFileName, err)
	}
	seen := map[string]bool{}
	for _, e := range l.Plugins {
		if !nameRe.MatchString(e.Name) {
			return nil, fmt.Errorf("%s: bad name %q", LockFileName, e.Name)
		}
		if !versionRe.MatchString(e.Version) {
			return nil, fmt.Errorf("%s: bad version %q", LockFileName, e.Version)
		}
		if e.Capabilities.Network != "none" && e.Capabilities.Network != "broker" {
			return nil, fmt.Errorf("%s: bad network %q", LockFileName, e.Capabilities.Network)
		}
		k := e.Name + "@" + e.Version
		if seen[k] {
			return nil, fmt.Errorf("%s: duplicate %s", LockFileName, k)
		}
		seen[k] = true
	}
	sort.Slice(l.Plugins, func(i, j int) bool {
		if l.Plugins[i].Name != l.Plugins[j].Name {
			return l.Plugins[i].Name < l.Plugins[j].Name
		}
		return CompareVersions(l.Plugins[i].Version, l.Plugins[j].Version) < 0
	})
	return &l, nil
}

// SaveLock writes the lock file with mode 0600.
func SaveLock(home string, l *Lock) error {
	if err := os.MkdirAll(filepath.Join(home, PluginsDirName), 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home, LockFileName), b, 0o600)
}

// Latest returns the newest entry per name (empty when the lock is).
func (l *Lock) Latest() map[string]LockEntry {
	out := map[string]LockEntry{}
	for _, e := range l.Plugins {
		cur, ok := out[e.Name]
		if !ok || CompareVersions(e.Version, cur.Version) > 0 {
			out[e.Name] = e
		}
	}
	return out
}

// Find returns the entry for name@version ("latest" resolves to the
// newest installed version).
func (l *Lock) Find(name, version string) (LockEntry, bool) {
	if version == "latest" {
		e, ok := l.Latest()[name]
		return e, ok
	}
	for _, e := range l.Plugins {
		if e.Name == name && e.Version == version {
			return e, true
		}
	}
	return LockEntry{}, false
}
