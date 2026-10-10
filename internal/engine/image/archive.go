package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/target"
)

// Limits bound what the engine will read from an image. The tarball is
// hostile input: a layer may be a decompression bomb, carry millions of
// entries, or use traversal names. Tests shrink these.
type Limits struct {
	LayerBytes         int64 // decompressed bytes per layer (spec: 2 GiB), headers included
	ImageBytes         int64 // decompressed bytes per image (spec: 8 GiB), headers included
	EntriesPerLayer    int   // tar entries per layer
	Entries            int   // tar entries per image, all layers and the outer archive together
	FileBytes          int64 // one collected file
	CollectedBytes     int64 // all collected files per image
	CollectedFiles     int   // collected files per image
	MetadataBytes      int64 // one manifest/index/config JSON
	MetadataTotalBytes int64 // all retained metadata blobs together
	Layers             int   // layers per image
	LockfilesPerTree   int   // lockfiles collected across the image
}

// DefaultLimits per Section 5.6.
var DefaultLimits = Limits{
	LayerBytes: 2 << 30, ImageBytes: 8 << 30, EntriesPerLayer: 500_000, Entries: 2_000_000, FileBytes: 32 << 20,
	CollectedBytes: 256 << 20, CollectedFiles: 512, MetadataBytes: 4 << 20, MetadataTotalBytes: 64 << 20, Layers: 256, LockfilesPerTree: 200,
}

// Fixed caps on hostile-input shapes that no legitimate image approaches.
const (
	maxEntryNameLen      = 4096   // PATH_MAX; longer names are counted hostile
	maxWhiteoutsPerLayer = 10_000 // further .wh. entries in a layer are counted hostile
	maxMetaEntries       = 256    // retained small JSON blobs (manifest, index, configs)
)

// ErrTooLarge is returned when a layer or the image exceeds the byte caps.
var ErrTooLarge = errors.New("image exceeds size cap")

// ErrUnsupportedLayer is returned for compression we cannot stream (zstd).
var ErrUnsupportedLayer = errors.New("unsupported layer compression")

// Contents is what a walk collected: the merged root filesystem view of the
// files the engine cares about, after whiteouts.
type Contents struct {
	Files   map[string][]byte // cleaned path (no leading slash) -> content
	Hostile int               // entries with absolute, traversal or over-long names, or excess whiteouts (skipped)
	Layers  int
	RPM     bool   // an rpm database path exists
	Source  string // "docker-archive" | "oci-layout"
}

// layer is the per-layer collection before merging.
type layer struct {
	files    map[string][]byte
	whiteout map[string]bool // paths removed by .wh. entries
	opaque   map[string]bool // directories emptied by .wh..wh..opq
}

func newLayer() *layer {
	return &layer{files: map[string][]byte{}, whiteout: map[string]bool{}, opaque: map[string]bool{}}
}

var sha256HexRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

// collector accumulates layers found while streaming an archive.
type collector struct {
	lim       Limits
	layers    map[string]*layer // keyed by archive entry name or blob digest
	meta      map[string][]byte // small JSON entries (manifest.json, index.json, blobs)
	metaBytes int64
	imageRead int64 // decompressed layer bytes streamed, headers included
	entries   int   // tar entries seen across the outer archive and every layer
	collected int64
	nfiles    int
	nlock     int
	hostile   int
	rpm       bool
}

func newCollector(lim Limits) *collector {
	return &collector{lim: lim, layers: map[string]*layer{}, meta: map[string][]byte{}}
}

// keepMeta retains a small JSON blob under the per-entry, count and total
// byte caps; false means it was dropped (the archive still parses if the
// manifest refers to it, and fails cleanly on the missing blob otherwise).
func (c *collector) keepMeta(size int64) bool {
	return size <= c.lim.MetadataBytes && len(c.meta) < maxMetaEntries && c.metaBytes+size <= c.lim.MetadataTotalBytes
}

func (c *collector) storeMeta(name string, b []byte) {
	c.meta[name] = b
	c.metaBytes += int64(len(b))
}

// cleanName validates a tar entry name: relative, no "..", no NUL, at most
// maxEntryNameLen bytes. ok is false for hostile names, which are counted
// and skipped (never written anywhere; this is defence in depth and a
// signal about the archive).
func cleanName(name string) (string, bool) {
	if name == "" || len(name) > maxEntryNameLen || strings.ContainsRune(name, 0) {
		return "", false
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return "", false
	}
	c := path.Clean(name)
	if c == "." {
		return "", false
	}
	if c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") {
		return "", false
	}
	return c, true
}

// interesting reports whether a cleaned path inside a layer should be kept.
func interesting(p string) (lockfile bool, keep bool) {
	switch p {
	case apkDB, dpkgStatus, osRelease, usrOSRelease:
		return false, true
	}
	if strings.HasPrefix(p, dpkgStatusD) && !strings.Contains(p[len(dpkgStatusD):], "/") {
		return false, true
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg == "node_modules" || seg == "vendor" || seg == ".git" || seg == "proc" || seg == "sys" {
			return false, false
		}
	}
	if _, ok := sca.ParserFor(path.Base(p)); ok {
		return true, true
	}
	return false, false
}

func isRPMPath(p string) bool {
	for _, r := range rpmDBPaths {
		if p == r {
			return true
		}
	}
	return false
}

// countingReader enforces a byte budget on a decompressed stream.
type countingReader struct {
	r     io.Reader
	n     *int64
	limit int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += int64(n)
	if *c.n > c.limit {
		return n, ErrTooLarge
	}
	return n, err
}

// decompress sniffs gzip (streamed) and zstd (refused); anything else is
// passed through as-is.
func decompress(r *bufio.Reader) (io.Reader, error) {
	head, _ := r.Peek(4)
	switch {
	case len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b:
		return gzip.NewReader(r)
	case len(head) >= 4 && bytes.Equal(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		return nil, ErrUnsupportedLayer
	}
	return r, nil
}

// tarWalker iterates a capped tar stream: EOF ends it, ErrTooLarge from the
// counting reader propagates unchanged, and the entry count is bounded per
// stream and (through total) across the whole image.
type tarWalker struct {
	tr       *tar.Reader
	what     string
	max      int
	entries  int
	total    *int // image-wide entry counter shared by every stream
	maxTotal int
}

// next returns the next header; done is true at EOF.
func (w *tarWalker) next() (hdr *tar.Header, done bool, err error) {
	hdr, err = w.tr.Next()
	if errors.Is(err, io.EOF) {
		return nil, true, nil
	}
	if err != nil {
		if errors.Is(err, ErrTooLarge) {
			return nil, false, ErrTooLarge
		}
		return nil, false, fmt.Errorf("%s: %w", w.what, err)
	}
	w.entries++
	if w.entries > w.max {
		return nil, false, fmt.Errorf("%s: more than %d entries", w.what, w.max)
	}
	*w.total++
	if *w.total > w.maxTotal {
		return nil, false, fmt.Errorf("image: more than %d tar entries in total", w.maxTotal)
	}
	return hdr, false, nil
}

func (c *collector) walker(tr *tar.Reader, what string) *tarWalker {
	return &tarWalker{tr: tr, what: what, max: c.lim.EntriesPerLayer, total: &c.entries, maxTotal: c.lim.Entries}
}

// nextEntry returns the next header with its cleaned name, skipping and
// counting entries with hostile names; done is true at EOF.
func (c *collector) nextEntry(w *tarWalker) (hdr *tar.Header, name string, done bool, err error) {
	for {
		hdr, done, err = w.next()
		if err != nil || done {
			return nil, "", done, err
		}
		if name, ok := cleanName(hdr.Name); ok {
			return hdr, name, false, nil
		}
		c.hostile++
	}
}

// readLayer streams one layer tar, keeping only interesting files. Every
// decompressed byte (headers, PAX records and bodies alike) is counted
// against both the layer and the image budget at the reader, so neither
// header sizes nor the entries' declared sizes can be used to under-report.
func (c *collector) readLayer(r io.Reader) (*layer, error) {
	var layerRead int64
	br := bufio.NewReaderSize(r, 64<<10)
	dr, err := decompress(br)
	if err != nil {
		return nil, err
	}
	perLayer := &countingReader{r: dr, n: &layerRead, limit: c.lim.LayerBytes}
	tr := tar.NewReader(&countingReader{r: perLayer, n: &c.imageRead, limit: c.lim.ImageBytes})
	w := c.walker(tr, "layer tar")
	l := newLayer()
	for {
		hdr, name, done, err := c.nextEntry(w)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		base := path.Base(name)
		if base == ".wh..wh..opq" || strings.HasPrefix(base, ".wh.") {
			if len(l.whiteout)+len(l.opaque) >= maxWhiteoutsPerLayer {
				c.hostile++
				continue
			}
			if base == ".wh..wh..opq" {
				l.opaque[path.Dir(name)] = true
			} else {
				l.whiteout[path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))] = true
			}
			continue
		}
		if isRPMPath(name) {
			c.rpm = true
		}
		// Symlinks and hardlinks are never followed: only regular file bodies
		// are read, and only for the paths we care about.
		if hdr.Typeflag != tar.TypeReg { // tar.Reader normalises legacy TypeRegA to TypeReg
			continue
		}
		lock, keep := interesting(name)
		if !keep || hdr.Size > c.lim.FileBytes {
			continue
		}
		if lock {
			if c.nlock >= c.lim.LockfilesPerTree {
				continue
			}
			c.nlock++
		}
		if c.nfiles >= c.lim.CollectedFiles || c.collected+hdr.Size > c.lim.CollectedBytes {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, c.lim.FileBytes+1))
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, ErrTooLarge
			}
			return l, err
		}
		if int64(len(b)) > c.lim.FileBytes {
			continue
		}
		c.nfiles++
		c.collected += int64(len(b))
		l.files[name] = b
	}
	return l, nil
}

// merge applies layers in order with whiteouts and returns the final view.
func merge(layers []*layer) map[string][]byte {
	out := map[string][]byte{}
	for _, l := range layers {
		for dir := range l.opaque {
			for p := range out {
				if strings.HasPrefix(p, dir+"/") {
					delete(out, p)
				}
			}
		}
		for w := range l.whiteout {
			delete(out, w)
			for p := range out {
				if strings.HasPrefix(p, w+"/") {
					delete(out, p)
				}
			}
		}
		for p, b := range l.files {
			out[p] = b
		}
	}
	return out
}

// Open reads a docker-archive tar (optionally gzipped) or an OCI layout
// directory at p and returns the merged interesting contents.
func Open(p string, lim Limits) (*Contents, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return openOCIDir(p, lim)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file or directory", p)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return openArchive(f, lim)
}

// dockerManifest is manifest.json inside `docker save` output.
type dockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// ociIndex / ociManifest are the OCI image-spec documents we read.
type ociIndex struct {
	Manifests []ociDescriptor `json:"manifests"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Platform  *struct {
		OS   string `json:"os"`
		Arch string `json:"architecture"`
	} `json:"platform"`
}

type ociManifest struct {
	Config ociDescriptor   `json:"config"`
	Layers []ociDescriptor `json:"layers"`
}

// openArchive streams a docker-archive tar once. Layers are collected as
// they appear (the manifest may come after them); ordering is applied from
// manifest.json (or index.json for OCI-in-tar) afterwards.
func openArchive(r io.Reader, lim Limits) (*Contents, error) {
	c, err := collectArchive(r, lim)
	if err != nil {
		return nil, err
	}
	order, source, err := c.layerOrder()
	if err != nil {
		return nil, err
	}
	return c.finish(order, source), nil
}

// collectArchive is the streaming pass of openArchive. The outer tar's
// bytes count against the image budget as streamed (compressed layer
// bodies there, decompressed again inside readLayer). Small JSON blobs are
// retained under keepMeta's caps whether they sit at the top level or under
// blobs/sha256/; a single pass cannot know which blobs the manifest will
// reference because the manifest may come last.
func collectArchive(r io.Reader, lim Limits) (*collector, error) {
	c := newCollector(lim)
	br := bufio.NewReaderSize(r, 64<<10)
	dr, err := decompress(br)
	if err != nil {
		return nil, err
	}
	var outerRead int64
	tr := tar.NewReader(&countingReader{r: dr, n: &outerRead, limit: lim.ImageBytes})
	w := c.walker(tr, "image tar")
	for {
		hdr, name, done, err := c.nextEntry(w)
		if err != nil {
			return nil, err
		}
		if done {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch {
		case name == "manifest.json" || name == "index.json" || strings.HasSuffix(name, ".json"):
			if !c.keepMeta(hdr.Size) {
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, lim.MetadataBytes))
			if err != nil {
				return nil, err
			}
			c.storeMeta(name, b)
		case strings.HasSuffix(name, "/layer.tar") || strings.HasPrefix(name, "blobs/sha256/"):
			if len(c.layers) >= lim.Layers {
				return nil, fmt.Errorf("image tar: more than %d layers", lim.Layers)
			}
			peek := bufio.NewReaderSize(tr, 64<<10)
			if !looksLikeArchive(peek) {
				// A config blob or other JSON stored under blobs/: keep when small.
				if c.keepMeta(hdr.Size) {
					b, err := io.ReadAll(io.LimitReader(peek, lim.MetadataBytes))
					if err != nil {
						return nil, err
					}
					c.storeMeta(name, b)
				}
				continue
			}
			l, err := c.readLayer(peek)
			if err != nil {
				return nil, fmt.Errorf("layer %s: %w", name, err)
			}
			c.layers[name] = l
		}
	}
	return c, nil
}

// looksLikeArchive peeks for gzip, zstd or a ustar header.
func looksLikeArchive(r *bufio.Reader) bool {
	head, _ := r.Peek(263)
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		return true
	}
	if len(head) >= 4 && bytes.Equal(head[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return true
	}
	return len(head) >= 263 && string(head[257:262]) == "ustar"
}

// layerOrder resolves the ordered layer keys from manifest.json, falling
// back to index.json (OCI layout stored in a tar).
func (c *collector) layerOrder() ([]string, string, error) {
	if b, ok := c.meta["manifest.json"]; ok {
		var ms []dockerManifest
		if err := json.Unmarshal(b, &ms); err != nil || len(ms) == 0 {
			return nil, "", fmt.Errorf("manifest.json: %v", errOr(err, "empty"))
		}
		var order []string
		for _, l := range ms[0].Layers { // first image only in multi-image archives
			n, ok := cleanName(l)
			if !ok {
				c.hostile++
				continue
			}
			order = append(order, n)
		}
		return order, "docker-archive", nil
	}
	if b, ok := c.meta["index.json"]; ok {
		order, err := c.ociOrder(b, func(d string) ([]byte, bool) { b, ok := c.meta["blobs/sha256/"+d]; return b, ok })
		return order, "oci-layout", err
	}
	if len(c.layers) == 0 {
		return nil, "", errors.New("not a container image archive (no manifest.json or index.json)")
	}
	// No manifest: use archive order (sorted names) so something is reported.
	var order []string
	for k := range c.layers {
		order = append(order, k)
	}
	sort.Strings(order)
	return order, "docker-archive", nil
}

func errOr(err error, s string) any {
	if err != nil {
		return err
	}
	return s
}

// ociOrder walks index -> (nested index) -> manifest -> layers, validating
// every digest as 64 hex chars so a digest can never name a path.
func (c *collector) ociOrder(index []byte, blob func(digest string) ([]byte, bool)) ([]string, error) {
	var idx ociIndex
	if err := json.Unmarshal(index, &idx); err != nil || len(idx.Manifests) == 0 {
		return nil, fmt.Errorf("index.json: %v", errOr(err, "no manifests"))
	}
	desc := idx.Manifests[0]
	for _, m := range idx.Manifests { // prefer linux/amd64 when a platform list is present
		if m.Platform != nil && m.Platform.OS == "linux" && m.Platform.Arch == "amd64" {
			desc = m
			break
		}
	}
	for hops := 0; hops < 2; hops++ {
		d := strings.TrimPrefix(desc.Digest, "sha256:")
		if !sha256HexRe.MatchString(d) {
			return nil, fmt.Errorf("index.json: bad digest %q", desc.Digest)
		}
		b, ok := blob(d)
		if !ok {
			return nil, fmt.Errorf("oci: blob %s missing", d)
		}
		if strings.Contains(desc.MediaType, "index") || strings.Contains(desc.MediaType, "manifest.list") {
			var nested ociIndex
			if err := json.Unmarshal(b, &nested); err != nil || len(nested.Manifests) == 0 {
				return nil, fmt.Errorf("oci nested index: %v", errOr(err, "no manifests"))
			}
			desc = nested.Manifests[0]
			continue
		}
		var m ociManifest
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("oci manifest: %w", err)
		}
		var order []string
		for _, l := range m.Layers {
			if strings.Contains(l.MediaType, "zstd") {
				return nil, ErrUnsupportedLayer
			}
			ld := strings.TrimPrefix(l.Digest, "sha256:")
			if !sha256HexRe.MatchString(ld) {
				return nil, fmt.Errorf("oci manifest: bad layer digest %q", l.Digest)
			}
			order = append(order, "blobs/sha256/"+ld)
		}
		return order, nil
	}
	return nil, errors.New("oci: index nesting too deep")
}

func (c *collector) finish(order []string, source string) *Contents {
	var ordered []*layer
	for _, k := range order {
		if l, ok := c.layers[k]; ok {
			ordered = append(ordered, l)
		}
	}
	return &Contents{Files: merge(ordered), Hostile: c.hostile, Layers: len(ordered), RPM: c.rpm, Source: source}
}

// openOCIDir reads an OCI image layout directory: oci-layout, index.json
// and blobs/sha256/<digest>. Blob paths are built from validated digests
// only; nothing in the index can name a file outside blobs/sha256.
func openOCIDir(dir string, lim Limits) (*Contents, error) {
	if err := target.ValidateOCILayout(dir); err != nil {
		return nil, err
	}
	index, err := readSmall(filepath.Join(dir, "index.json"), lim.MetadataBytes)
	if err != nil {
		return nil, err
	}
	c := newCollector(lim)
	blob := func(d string) ([]byte, bool) {
		b, err := readSmall(filepath.Join(dir, "blobs", "sha256", d), lim.MetadataBytes)
		return b, err == nil
	}
	order, err := c.ociOrder(index, blob)
	if err != nil {
		return nil, err
	}
	if len(order) > lim.Layers {
		return nil, fmt.Errorf("oci: more than %d layers", lim.Layers)
	}
	for _, key := range order {
		p := filepath.Join(dir, filepath.FromSlash(key))
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			return nil, fmt.Errorf("oci: layer %s is missing or not a regular file", key)
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		l, err := c.readLayer(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("layer %s: %w", key, err)
		}
		c.layers[key] = l
	}
	return c.finish(order, "oci-layout"), nil
}

// readSmall reads a regular file (not a symlink) of at most max bytes.
func readSmall(p string, max int64) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s: exceeds %d bytes", p, max)
	}
	return os.ReadFile(p)
}
