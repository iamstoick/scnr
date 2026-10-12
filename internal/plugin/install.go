package plugin

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InstallOptions controls Install.
type InstallOptions struct {
	Home             string
	RequireSignature bool
	TrustedKeys      []ed25519.PublicKey
	// AllowUnsigned permits the interactive sha256 ceremony below. The
	// caller passes the --allow-unsigned flag; non-TTY callers must
	// leave IsTTY false and the install is refused.
	AllowUnsigned bool
	IsTTY         bool
	Stdin         io.Reader
	Stdout        io.Writer
	Now           func() time.Time
	InstalledBy   string
	// Audit receives the install row (action, detail).
	Audit func(action string, detail map[string]any)
}

func (o InstallOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

// staged is an install candidate: exact manifest bytes, optional
// signature, binary name and bytes.
type staged struct {
	manifest []byte
	sig      []byte // raw 64 bytes or nil
	binName  string
	bin      []byte
}

// Install stages a plugin from a local directory or .tar.gz file,
// verifies trust, and records it in the lock file.
func Install(src string, o InstallOptions) (*LockEntry, error) {
	fi, err := os.Stat(src)
	if err != nil {
		return nil, err
	}
	var st *staged
	if fi.IsDir() {
		st, err = stageDir(src)
	} else if strings.HasSuffix(strings.ToLower(src), ".tar.gz") || strings.HasSuffix(strings.ToLower(src), ".tgz") {
		st, err = stageTarball(src)
	} else {
		return nil, fmt.Errorf("install %s: want a directory or .tar.gz file", src)
	}
	if err != nil {
		return nil, err
	}
	m, _, err := ParseManifest(st.manifest)
	if err != nil {
		return nil, err
	}
	if st.binName != BinaryName(m.Name) {
		return nil, fmt.Errorf("install: payload %q does not match manifest name %q", st.binName, m.Name)
	}
	binHash := sha256.Sum256(st.bin)
	if hex.EncodeToString(binHash[:]) != m.BinarySHA256 {
		return nil, fmt.Errorf("install: manifest binary_sha256 does not match the payload")
	}
	pubKey, err := checkTrust(st, o)
	if err != nil {
		return nil, err
	}
	l, err := LoadLock(o.Home)
	if err != nil {
		return nil, err
	}
	if _, ok := l.Find(m.Name, m.Version); ok {
		return nil, fmt.Errorf("install: %s@%s is already installed (remove it first)", m.Name, m.Version)
	}
	if err := checkDowngrade(l, m, o); err != nil {
		return nil, err
	}
	dest := Dir(o.Home, m.Name, m.Version)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, err
	}
	// Exact staged bytes: the signature covers these manifest bytes.
	if err := os.WriteFile(filepath.Join(dest, "manifest.json"), st.manifest, 0o600); err != nil {
		return nil, err
	}
	if st.sig != nil {
		if err := os.WriteFile(filepath.Join(dest, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(st.sig)+"\n"), 0o600); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dest, st.binName), st.bin, 0o700); err != nil {
		return nil, err
	}
	manHash := sha256.Sum256(st.manifest)
	entry := LockEntry{
		Name: m.Name, Version: m.Version,
		BinarySHA256: m.BinarySHA256, ManifestSHA256: hex.EncodeToString(manHash[:]),
		PublisherKey: pubKey, Capabilities: LockCapabilities{Network: m.Capabilities.Network},
		InstalledAt: o.now(), InstalledBy: o.InstalledBy,
	}
	l.Plugins = append(l.Plugins, entry)
	if err := SaveLock(o.Home, l); err != nil {
		return nil, err
	}
	if o.Audit != nil {
		o.Audit("plugin_install", map[string]any{
			"name": m.Name, "version": m.Version,
			"binary_sha256": m.BinarySHA256, "manifest_sha256": entry.ManifestSHA256,
			"publisher_key": pubKey, "network": m.Capabilities.Network,
			"installed_by": o.InstalledBy,
		})
	}
	return &entry, nil
}

// checkTrust verifies the staged signature or runs the interactive
// unsigned ceremony. It returns the lock publisher_key value. A present
// signature must verify — a corrupt one never falls through to the
// unsigned path.
func checkTrust(st *staged, o InstallOptions) (string, error) {
	if st.sig != nil {
		if len(st.sig) != ed25519.SignatureSize {
			return "", fmt.Errorf("install: malformed signature (%d bytes, want 64)", len(st.sig))
		}
		for _, k := range o.TrustedKeys {
			if ed25519.Verify(k, st.manifest, st.sig) {
				return fingerprint(k), nil
			}
		}
		if len(o.TrustedKeys) == 0 {
			return "", fmt.Errorf("install: signature present but no plugins.trusted_keys are configured")
		}
		return "", fmt.Errorf("install: signature does not verify against %d trusted key(s)", len(o.TrustedKeys))
	}
	if o.RequireSignature {
		return "", fmt.Errorf("install: missing signature (require_signature is on)")
	}
	if !o.AllowUnsigned || !o.IsTTY {
		return "", fmt.Errorf("install: unsigned plugin refused (require_signature is off but this needs --allow-unsigned on a terminal)")
	}
	sum := sha256.Sum256(st.manifest)
	fmt.Fprintf(o.Stdout, "unsigned plugin manifest sha256:\n  %s\ntype the first 16 characters to install it anyway: ", hex.EncodeToString(sum[:]))
	line, err := bufio.NewReader(o.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("install: %w", err)
	}
	if strings.TrimSpace(line) != hex.EncodeToString(sum[:])[:16] {
		return "", fmt.Errorf("install: confirmation mismatch, refusing unsigned plugin")
	}
	return "unsigned", nil
}

// checkDowngrade prompts when the staged version is older than the
// newest installed one.
func checkDowngrade(l *Lock, m *Manifest, o InstallOptions) error {
	cur, ok := l.Latest()[m.Name]
	if !ok || CompareVersions(m.Version, cur.Version) >= 0 {
		return nil
	}
	if !o.IsTTY {
		return fmt.Errorf("install: %s@%s is older than installed %s (downgrade needs a terminal)", m.Name, m.Version, cur.Version)
	}
	fmt.Fprintf(o.Stdout, "warning: %s@%s is older than installed %s; type \"yes\" to downgrade: ", m.Name, m.Version, cur.Version)
	line, err := bufio.NewReader(o.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if strings.TrimSpace(line) != "yes" {
		return fmt.Errorf("install: downgrade declined")
	}
	return nil
}

// stageDir stages an install from a directory: manifest.json plus exactly
// one scnr-plugin-* payload and an optional manifest.sig.
func stageDir(dir string) (*staged, error) {
	man, err := readCappedFile(filepath.Join(dir, "manifest.json"), MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	var st staged
	st.manifest = man
	if sig, err := readCappedFile(filepath.Join(dir, "manifest.sig"), MaxSignatureBytes); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil {
			return nil, fmt.Errorf("manifest.sig: %w", err)
		}
		st.sig = raw
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "manifest.json" || name == "manifest.sig" {
			continue
		}
		if !strings.HasPrefix(name, "scnr-plugin-") || !nameRe.MatchString(strings.TrimPrefix(name, "scnr-plugin-")) {
			return nil, fmt.Errorf("install: unexpected file %q (want manifest.json, manifest.sig, scnr-plugin-<name>)", name)
		}
		if st.binName != "" {
			return nil, fmt.Errorf("install: two payloads (%q and %q)", st.binName, name)
		}
		bin, err := readCappedFile(filepath.Join(dir, name), MaxTarballBytes)
		if err != nil {
			return nil, err
		}
		st.binName, st.bin = name, bin
	}
	if st.binName == "" {
		return nil, fmt.Errorf("install: no scnr-plugin-<name> payload in %s", dir)
	}
	return &st, nil
}

// stageTarball stages an install from a .tar.gz with the bundle's tar
// hardening: entry cap, regular files only, fixed name grammar, size caps.
func stageTarball(path string) (*staged, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxTarballBytes {
		return nil, fmt.Errorf("install: tarball %d bytes, cap %d", fi.Size(), MaxTarballBytes)
	}
	gz, err := gzip.NewReader(io.LimitReader(f, MaxTarballBytes+1))
	if err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, MaxTarballBytes+1))
	var st staged
	seen := map[string]bool{}
	for n := 0; ; n++ {
		if n >= MaxTarEntries {
			return nil, fmt.Errorf("install: over %d tar entries", MaxTarEntries)
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch {
		case name == "manifest.json":
		case name == "manifest.sig":
		case strings.HasPrefix(name, "scnr-plugin-") && nameRe.MatchString(strings.TrimPrefix(name, "scnr-plugin-")):
		default:
			return nil, fmt.Errorf("install: tar entry %q outside the fixed grammar", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("install: tar entry %q is not a regular file", hdr.Name)
		}
		if seen[name] {
			return nil, fmt.Errorf("install: duplicate tar entry %q", hdr.Name)
		}
		seen[name] = true
		cap := int64(MaxTarballBytes)
		if name == "manifest.json" {
			cap = MaxManifestBytes
		} else if name == "manifest.sig" {
			cap = MaxSignatureBytes
		}
		b, err := io.ReadAll(io.LimitReader(tr, cap+1))
		if err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		if int64(len(b)) > cap {
			return nil, fmt.Errorf("install: tar entry %q over %d bytes", hdr.Name, cap)
		}
		switch name {
		case "manifest.json":
			st.manifest = b
		case "manifest.sig":
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
			if err != nil {
				return nil, fmt.Errorf("install: manifest.sig: %w", err)
			}
			st.sig = raw
		default:
			if st.binName != "" {
				return nil, fmt.Errorf("install: two payloads (%q and %q)", st.binName, name)
			}
			st.binName, st.bin = name, b
		}
	}
	if st.manifest == nil {
		return nil, fmt.Errorf("install: no manifest.json in tarball")
	}
	if st.binName == "" {
		return nil, fmt.Errorf("install: no scnr-plugin-<name> payload in tarball")
	}
	return &st, nil
}

func readCappedFile(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: over %d bytes", path, max)
	}
	return b, nil
}

// SignManifest sets binary_sha256 in dir/manifest.json to the payload's
// hash and writes dir/manifest.sig over the resulting bytes. It is the
// publisher side of install verification.
func SignManifest(dir string, seed []byte) error {
	raw, err := readCappedFile(filepath.Join(dir, "manifest.json"), MaxManifestBytes)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	name, _ := m["name"].(string)
	if !nameRe.MatchString(name) {
		return fmt.Errorf("manifest.json: bad name %q", name)
	}
	bin, err := readCappedFile(filepath.Join(dir, BinaryName(name)), MaxTarballBytes)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	m["binary_sha256"] = hex.EncodeToString(sum[:])
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if _, _, err := ParseManifest(out); err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("sign: bad seed length")
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), out)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.sig"), []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600)
}

// Remove deletes installed versions (version "" removes all) and drops
// their lock entries. It returns the removed entries.
func Remove(home, name, version string, audit func(action string, detail map[string]any)) ([]LockEntry, error) {
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("remove: bad name %q", name)
	}
	l, err := LoadLock(home)
	if err != nil {
		return nil, err
	}
	var kept, removed []LockEntry
	for _, e := range l.Plugins {
		if e.Name == name && (version == "" || e.Version == version) {
			removed = append(removed, e)
		} else {
			kept = append(kept, e)
		}
	}
	if len(removed) == 0 {
		if version == "" {
			return nil, fmt.Errorf("remove: %s is not installed", name)
		}
		return nil, fmt.Errorf("remove: %s@%s is not installed", name, version)
	}
	for _, e := range removed {
		if err := os.RemoveAll(Dir(home, e.Name, e.Version)); err != nil {
			return nil, err
		}
		// Drop the name directory when its last version goes.
		entries, _ := os.ReadDir(filepath.Join(home, PluginsDirName, e.Name))
		if len(entries) == 0 {
			_ = os.Remove(filepath.Join(home, PluginsDirName, e.Name))
		}
		if audit != nil {
			audit("plugin_remove", map[string]any{"name": e.Name, "version": e.Version})
		}
	}
	l.Plugins = kept
	if err := SaveLock(home, l); err != nil {
		return nil, err
	}
	return removed, nil
}
