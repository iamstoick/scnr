package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile streams a file's SHA-256 hex digest.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Verify re-hashes the installed binary and manifest against the lock
// entry. Any drift — a swapped binary, an edited manifest — is an
// integrity failure: the plugin is skipped and audited, never run.
func Verify(home string, e LockEntry) error {
	id := e.Name + "@" + e.Version
	bin, err := HashFile(BinaryPath(home, e))
	if err != nil {
		return fmt.Errorf("plugin %s: binary: %w", id, err)
	}
	if bin != e.BinarySHA256 {
		return fmt.Errorf("plugin %s: binary hash mismatch (lock %.16s, disk %.16s)", id, e.BinarySHA256, bin)
	}
	man, err := HashFile(ManifestPath(home, e))
	if err != nil {
		return fmt.Errorf("plugin %s: manifest: %w", id, err)
	}
	if man != e.ManifestSHA256 {
		return fmt.Errorf("plugin %s: manifest drift (lock %.16s, disk %.16s)", id, e.ManifestSHA256, man)
	}
	return nil
}
