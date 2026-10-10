package engine

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Walk limits (Section 5.5): shared by secrets (Phase 1) and codecheck.
const (
	MaxFileBytes = 5 << 20
	sniffBytes   = 512
)

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".hg": true, ".svn": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true, "dist": true, "build": true,
	".idea": true, ".vscode": true, ".scnr": true, "scnr-out": true,
}

// WalkStats counts what was skipped.
type WalkStats struct {
	Files      int
	SkippedBig int
	SkippedBin int
}

// WalkFunc receives each regular text file with its root-relative path and
// full content (<= MaxFileBytes).
type WalkFunc func(rel string, content []byte) error

// WalkFiles walks root honouring a top-level .gitignore (simple patterns),
// skipping VCS/dependency dirs, binaries (sniffed) and files > MaxFileBytes.
// Symlinks are not followed. Depth is capped at 32.
func WalkFiles(ctx context.Context, root string, fn WalkFunc) (WalkStats, error) {
	var st WalkStats
	ignore := loadGitignore(root)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are skipped, not fatal
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || ignore.match(rel, true) || strings.Count(rel, string(filepath.Separator)) >= 32) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // symlinks, devices
		}
		if ignore.match(rel, false) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > MaxFileBytes {
			st.SkippedBig++
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if isBinary(b) {
			st.SkippedBin++
			return nil
		}
		st.Files++
		return fn(filepath.ToSlash(rel), b)
	})
	return st, err
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > sniffBytes {
		n = sniffBytes
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}

// gitignore is a minimal matcher: supports comments, negation-less patterns,
// trailing "/" for dirs, leading "/" for root-anchored, and "*" globs via
// filepath.Match on the basename or the relative path.
type gitignore struct {
	patterns []string
	dirOnly  []bool
	anchored []bool
}

func loadGitignore(root string) *gitignore {
	g := &gitignore{}
	f, err := os.Open(filepath.Join(root, ".gitignore"))
	if err != nil {
		return g
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		dirOnly := strings.HasSuffix(line, "/")
		line = strings.TrimSuffix(line, "/")
		anchored := strings.HasPrefix(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		g.patterns = append(g.patterns, line)
		g.dirOnly = append(g.dirOnly, dirOnly)
		g.anchored = append(g.anchored, anchored)
	}
	return g
}

func (g *gitignore) match(rel string, isDir bool) bool {
	rel = filepath.ToSlash(rel)
	base := rel
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		base = rel[i+1:]
	}
	for i, p := range g.patterns {
		if g.dirOnly[i] && !isDir {
			continue
		}
		if g.anchored[i] || strings.Contains(p, "/") {
			if ok, _ := filepath.Match(p, rel); ok {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
	}
	return false
}
