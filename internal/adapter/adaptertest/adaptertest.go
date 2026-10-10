// Package adaptertest provides fake tool binaries for adapter tests. A fake
// is a small shell script placed first on PATH that records its argv and
// replays a fixture; tests never run the real tools or touch the network.
package adaptertest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FixtureDir returns testdata/adapters/<tool>/<version> relative to the repo
// root, resolved from the calling package directory.
func FixtureDir(t *testing.T, tool, version string) string {
	t.Helper()
	for _, up := range []string{"../../../testdata", "../../testdata", "../testdata", "testdata"} {
		p := filepath.Join(up, "adapters", tool, version)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	t.Fatalf("fixture dir for %s %s not found", tool, version)
	return ""
}

// Install writes a fake binary named tool into a temp dir, prepends that dir
// to PATH and points TMPDIR at a scratch dir. The script prints versionLine
// for the version flag, otherwise records "$@" to <argvFile> and runs body
// (a sh snippet; $OUT holds the value following -o when present).
// It returns the argv file path.
func Install(t *testing.T, tool, versionFlag, versionLine, body string) string {
	t.Helper()
	dir := t.TempDir()
	argv := filepath.Join(dir, tool+".argv")
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = \"" + versionFlag + "\" ]; then echo '" + versionLine + "'; exit 0; fi\n" +
		"printf '%s\\n' \"$@\" > '" + argv + "'\n" +
		"OUT=''\nprev=''\nfor a in \"$@\"; do if [ \"$prev\" = \"-o\" ]; then OUT=\"$a\"; fi; prev=\"$a\"; done\n" +
		body + "\n"
	if err := os.WriteFile(filepath.Join(dir, tool), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TMPDIR", t.TempDir())
	return argv
}

// CatBody returns a script body that prints file to stdout using only shell
// builtins, so the fake works even when PATH holds no coreutils.
func CatBody(file string) string {
	return `while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line"; done < '` + file + `'`
}

// CopyToOutBody returns a script body that copies file to the path given
// after -o (builtins only).
func CopyToOutBody(file string) string {
	return `: > "$OUT"; while IFS= read -r line || [ -n "$line" ]; do printf '%s\n' "$line" >> "$OUT"; done < '` + file + `'`
}

// Argv reads the recorded argument list.
func Argv(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fake binary was not invoked: %v", err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// Hide makes tool unresolvable by setting PATH to an empty directory.
func Hide(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}
