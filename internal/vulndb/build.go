package vulndb

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/engine/sca"
)

// Builder constants.
const (
	// GCSHost is the OSV export bucket, the only host `db bundle build`
	// contacts. doctor lists it.
	GCSHost = "osv-vulnerabilities.storage.googleapis.com"
	// DefaultBundleBase is the export base URL.
	DefaultBundleBase = "https://" + GCSHost
	// MaxZipEntryBytes caps one OSV record inside all.zip (matches the OSV
	// API body cap).
	MaxZipEntryBytes = 16 << 20
	// MaxBuildBytes caps the total bytes downloaded and decompressed across
	// every ecosystem in one build.
	MaxBuildBytes = 2 << 30
	// MaxZipEntries caps records per ecosystem archive.
	MaxZipEntries = 2_000_000
)

var ecosystemRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.:-]{0,31}$`)

// Builder downloads OSV exports and writes a bundle.
type Builder struct {
	// HTTP must be an endpoint client restricted to GCSHost (or the test
	// server's host): the builder never constructs its own.
	HTTP       *http.Client
	Out        string
	Ecosystems []string
	// SignSeed signs the manifest when set; an unsigned bundle loads only
	// with --allow-unsigned.
	SignSeed []byte
	Log      *slog.Logger
	// Base overrides DefaultBundleBase (tests).
	Base string
	// Builder is recorded in the manifest ("scnr <version>").
	Builder string
	Now     func() time.Time
}

// BuildResult is what Build produced.
type BuildResult struct {
	Manifest Manifest
	Path     string
	// Skipped counts zip entries dropped for size or malformed JSON.
	Skipped int
}

// Build fetches each ecosystem's all.zip, normalises every record into
// affected lines, writes the bundle to Out and returns its manifest.
func (b *Builder) Build(ctx context.Context) (BuildResult, error) {
	var res BuildResult
	if b.HTTP == nil {
		return res, errors.New("bundle build: no HTTP client")
	}
	if len(b.Ecosystems) == 0 {
		return res, errors.New("bundle build: no ecosystems")
	}
	now := b.Now
	if now == nil {
		now = time.Now
	}
	base := b.Base
	if base == "" {
		base = DefaultBundleBase
	}
	names := map[string]string{}
	for _, eco := range b.Ecosystems {
		if !ecosystemRe.MatchString(eco) {
			return res, fmt.Errorf("bundle build: bad ecosystem name %q", eco)
		}
		name := "affected/" + fileStem(eco) + ".jsonl"
		if !entryNameRe.MatchString(name) {
			return res, fmt.Errorf("bundle build: ecosystem %q has no valid file name", eco)
		}
		if prev, dup := names[name]; dup {
			return res, fmt.Errorf("bundle build: ecosystems %q and %q map to the same file", prev, eco)
		}
		names[name] = eco
	}
	if err := os.MkdirAll(b.Out, 0o700); err != nil {
		return res, err
	}
	work, err := os.MkdirTemp(b.Out, ".build-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // best-effort temp cleanup

	budget := int64(MaxBuildBytes)
	var files []FileEntry
	for _, eco := range b.Ecosystems {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		fe, skipped, err := b.buildEcosystem(ctx, base, eco, work, &budget)
		if err != nil {
			return res, fmt.Errorf("bundle build: %s: %w", eco, err)
		}
		res.Skipped += skipped
		files = append(files, fe)
		if b.Log != nil {
			b.Log.Info("bundle: ecosystem done", "ecosystem", eco, "records", fe.Records, "bytes", fe.Bytes)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	m := Manifest{SchemaVersion: BundleSchemaVersion, CreatedAt: now().UTC().Truncate(time.Second), Builder: b.Builder, Source: "osv.dev", Ecosystems: append([]string(nil), b.Ecosystems...), Files: files}
	if m.Builder == "" {
		m.Builder = "scnr"
	}
	manifestBytes, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return res, err
	}
	entries := []tarEntry{{Name: manifestName, Body: manifestBytes}}
	if len(b.SignSeed) > 0 {
		sig := base64.StdEncoding.EncodeToString(Sign(b.SignSeed, manifestBytes)) + "\n"
		entries = append(entries, tarEntry{Name: signatureName, Body: []byte(sig)})
	}
	for _, f := range files {
		entries = append(entries, tarEntry{Name: f.Name, Path: filepath.Join(work, filepath.FromSlash(f.Name)), Size: f.Bytes})
	}
	// The bundle is assembled inside the 0700 work dir and renamed into
	// place, so --out never sees a half-written file and the final name is
	// never opened for writing where a symlink could redirect it.
	res.Path = filepath.Join(b.Out, "scnr-osv-"+m.CreatedAt.Format("20060102")+".tar.gz")
	tmp := filepath.Join(work, "bundle.tar.gz")
	if err := writeBundle(tmp, entries); err != nil {
		return res, err
	}
	if err := moveIntoPlace(tmp, res.Path); err != nil {
		return res, err
	}
	res.Manifest = m
	return res, nil
}

// moveIntoPlace renames a finished bundle onto dst, refusing when dst
// exists and is not a regular file (a symlink would be replaced, not
// followed, but a planted link is a sign of tampering, not a bundle to
// overwrite).
func moveIntoPlace(src, dst string) error {
	st, err := os.Lstat(dst)
	switch {
	case err == nil && st.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("bundle build: %s: is a symbolic link; refusing to replace it", dst)
	case err == nil && !st.Mode().IsRegular():
		return fmt.Errorf("bundle build: %s: exists and is not a regular file", dst)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("bundle build: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("bundle build: %w", err)
	}
	return nil
}

// fileStem maps an ecosystem to its lowercase entry-name stem.
func fileStem(eco string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		}
		return '-'
	}, eco)
}

// buildEcosystem downloads one all.zip to a temp file (the zip central
// directory lives at the end, so it cannot be streamed) and writes the
// normalised affected lines.
func (b *Builder) buildEcosystem(ctx context.Context, base, eco, work string, budget *int64) (FileEntry, int, error) {
	zipPath, zipSize, err := b.download(ctx, base+"/"+url.PathEscape(eco)+"/all.zip", work, budget)
	if err != nil {
		return FileEntry{}, 0, err
	}
	defer os.Remove(zipPath) //nolint:errcheck // best-effort temp cleanup
	zf, err := os.Open(zipPath)
	if err != nil {
		return FileEntry{}, 0, err
	}
	defer zf.Close()
	zr, err := zip.NewReader(zf, zipSize)
	if err != nil {
		return FileEntry{}, 0, fmt.Errorf("all.zip: %w", err)
	}
	if len(zr.File) > MaxZipEntries {
		return FileEntry{}, 0, fmt.Errorf("all.zip: %d entries (max %d)", len(zr.File), MaxZipEntries)
	}
	name := "affected/" + fileStem(eco) + ".jsonl"
	outPath := filepath.Join(work, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		return FileEntry{}, 0, err
	}
	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return FileEntry{}, 0, err
	}
	defer out.Close()
	h := sha256.New()
	w := io.MultiWriter(out, h)
	fe := FileEntry{Name: name}
	skipped := 0
	for _, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return fe, skipped, err
		}
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") || f.UncompressedSize64 > MaxZipEntryBytes {
			skipped++
			continue
		}
		rc, err := f.Open()
		if err != nil {
			skipped++
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxZipEntryBytes+1))
		rc.Close() //nolint:errcheck // zip entry fully read; read error is the real one
		if err != nil || len(data) > MaxZipEntryBytes {
			skipped++
			continue
		}
		*budget -= int64(len(data))
		if *budget < 0 {
			return fe, skipped, fmt.Errorf("build exceeds %d decompressed bytes", MaxBuildBytes)
		}
		var v sca.Vuln
		if err := json.Unmarshal(data, &v); err != nil || v.ID == "" {
			skipped++
			continue
		}
		for _, rec := range sca.RecordsFromVuln(&v, eco) {
			line, err := json.Marshal(rec)
			if err != nil {
				skipped++
				continue
			}
			// Round-trip through the strict decoder so the bundle only ever
			// contains lines the loader will accept.
			if _, err := sca.DecodeRecord(line); err != nil {
				skipped++
				continue
			}
			line = append(line, '\n')
			if _, err := w.Write(line); err != nil {
				return fe, skipped, err
			}
			fe.Bytes += int64(len(line))
			fe.Records++
		}
	}
	if err := out.Close(); err != nil {
		return fe, skipped, err
	}
	fe.SHA256 = hex.EncodeToString(h.Sum(nil))
	return fe, skipped, nil
}

// download fetches u to a temp file under work, bounded by budget.
func (b *Builder) download(ctx context.Context, u, work string, budget *int64) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "scnr")
	resp, err := b.HTTP.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("fetch %s: %w", u, err)
	}
	defer resp.Body.Close() //nolint:errcheck // download cleanup
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("fetch %s: HTTP %d", u, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(work, "osv-*.zip")
	if err != nil {
		return "", 0, err
	}
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, *budget+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp.Name()) //nolint:errcheck // best effort; the fetch error is the real one
		return "", 0, fmt.Errorf("fetch %s: %w", u, err)
	}
	if n > *budget {
		os.Remove(tmp.Name()) //nolint:errcheck // best effort; the budget error is the real one
		return "", 0, fmt.Errorf("fetch %s: exceeds the %d byte build budget", u, MaxBuildBytes)
	}
	*budget -= n
	return tmp.Name(), n, nil
}

// tarEntry is one file to pack: an in-memory Body or a Path on disk.
type tarEntry struct {
	Name string
	Body []byte
	Path string
	Size int64
}

// writeBundle packs entries, in order, into a gzipped tar at path (0644:
// bundles are made to be copied to other machines).
func writeBundle(path string, entries []tarEntry) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		size := int64(len(e.Body))
		if e.Path != "" {
			size = e.Size
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.Name, Mode: 0o644, Size: size, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0).UTC()}); err != nil {
			return err
		}
		if e.Path != "" {
			src, err := os.Open(e.Path)
			if err != nil {
				return err
			}
			_, err = io.CopyN(tw, src, size)
			src.Close()
			if err != nil {
				return err
			}
			continue
		}
		if _, err := tw.Write(e.Body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
