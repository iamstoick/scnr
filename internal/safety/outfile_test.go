package safety

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateOutputFile(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("keep"), 0o600)

	// Symlink: refused, target untouched.
	link := filepath.Join(dir, "link")
	os.Symlink(victim, link)
	if _, err := CreateOutputFile(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink accepted: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("target truncated: %q", b)
	}
	// Dangling symlink: still refused (would otherwise create the target).
	os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling"))
	if _, err := CreateOutputFile(filepath.Join(dir, "dangling")); err == nil {
		t.Fatal("dangling symlink accepted")
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); err == nil {
		t.Fatal("dangling symlink target was created")
	}
	// Directory and other non-regular targets: refused.
	if _, err := CreateOutputFile(dir); err == nil {
		t.Fatal("directory accepted")
	}
	// New file: created with the restricted mode; existing regular file:
	// truncated.
	p := filepath.Join(dir, "sub", "out.json")
	os.MkdirAll(filepath.Dir(p), 0o750)
	f, err := CreateOutputFile(p)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("12345")
	f.Close()
	if st, _ := os.Stat(p); st.Mode().Perm()&0o007 != 0 || st.Mode().Perm()&0o600 != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	f, err = CreateOutputFile(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(p); st.Size() != 0 {
		t.Fatal("existing regular file not truncated")
	}
}
