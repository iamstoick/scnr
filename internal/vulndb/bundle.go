package vulndb

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/engine/sca"
	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/store"
)

// Bundle format constants (Phase 4a). A bundle is a trust decision, not a
// scanned artefact: every deviation from the fixed shape is a hard error.
const (
	// BundleSchemaVersion is the manifest schema this build reads.
	BundleSchemaVersion = 1
	// MaxManifestBytes caps manifest.json.
	MaxManifestBytes = 1 << 20
	// MaxSignatureBytes caps manifest.sig (base64 of 64 bytes plus newline).
	MaxSignatureBytes = 1 << 10
	// MaxBundleDecompressed caps the whole decompressed tar stream.
	MaxBundleDecompressed = 2 << 30
	// MaxBundleEntries caps tar entries, manifest and signature included.
	MaxBundleEntries = 64
	// MaxBundleLineBytes caps one affected/*.jsonl line.
	MaxBundleLineBytes = sca.MaxRecordBytes
	// OfflineStaleAfter is when doctor warns an offline bundle is old.
	OfflineStaleAfter = 30 * 24 * time.Hour
	// MaxCreatedAtSkew is how far in the future a manifest's created_at may
	// be (clock drift); anything later is refused so a bundle cannot claim
	// a date that blocks every later real bundle as a downgrade.
	MaxCreatedAtSkew = 24 * time.Hour
	// KeyFileName is the signing key file under the scnr home.
	KeyFileName = "bundle-signing.key"

	manifestName  = "manifest.json"
	signatureName = "manifest.sig"
	kevName       = "kev.json"
	epssName      = "epss.csv"
	keyPrefix     = "ed25519:"
	seedPrefix    = "ed25519-seed:"
)

// entryNameRe is the whole entry-name grammar; anything else is refused.
var entryNameRe = regexp.MustCompile(`^(manifest\.json|manifest\.sig|kev\.json|epss\.csv|affected/[a-z0-9.-]{1,32}\.jsonl)$`)

var (
	// ErrBadBundle wraps every format violation (name grammar, caps,
	// manifest mismatch, digest mismatch, malformed record).
	ErrBadBundle = errors.New("bad bundle")
	// ErrBundleTooLarge is returned when the decompressed stream exceeds the cap.
	ErrBundleTooLarge = fmt.Errorf("%w: decompressed size over cap", ErrBadBundle)
	// ErrBundleOlder is returned (wrapped in a RefusalError) when a bundle's
	// created_at is older than the osv-offline data already loaded and
	// allowDowngrade is not set: replaying an old bundle would roll back
	// advisories.
	ErrBundleOlder = errors.New("bundle is older than the loaded osv-offline data")
	sha256Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// StaleAfterFor returns the staleness threshold for a vulndb source.
func StaleAfterFor(source string) time.Duration {
	if source == store.SourceOSVOffline {
		return OfflineStaleAfter
	}
	return StaleAfter
}

// Manifest is manifest.json.
type Manifest struct {
	SchemaVersion int         `json:"schema_version"`
	CreatedAt     time.Time   `json:"created_at"`
	Builder       string      `json:"builder"`
	Source        string      `json:"source"`
	Ecosystems    []string    `json:"ecosystems"`
	Files         []FileEntry `json:"files"`
	KEV           *FileEntry  `json:"kev,omitempty"`
	EPSS          *FileEntry  `json:"epss,omitempty"`
}

// FileEntry describes one data file in the bundle.
type FileEntry struct {
	Name    string `json:"name"`
	SHA256  string `json:"sha256"`
	Bytes   int64  `json:"bytes"`
	Records int64  `json:"records"`
}

// entries returns every data file the manifest declares, keyed by name.
func (m *Manifest) entries() map[string]FileEntry {
	out := make(map[string]FileEntry, len(m.Files)+2)
	for _, f := range m.Files {
		out[f.Name] = f
	}
	if m.KEV != nil {
		out[m.KEV.Name] = *m.KEV
	}
	if m.EPSS != nil {
		out[m.EPSS.Name] = *m.EPSS
	}
	return out
}

// validate checks the manifest's own shape (names, digests, counts) and
// that created_at is not more than MaxCreatedAtSkew after now.
func (m *Manifest) validate(now time.Time) error {
	if m.SchemaVersion != BundleSchemaVersion {
		return fmt.Errorf("%w: schema_version %d (want %d)", ErrBadBundle, m.SchemaVersion, BundleSchemaVersion)
	}
	if m.CreatedAt.IsZero() {
		return fmt.Errorf("%w: created_at missing", ErrBadBundle)
	}
	if m.CreatedAt.After(now.Add(MaxCreatedAtSkew)) {
		return fmt.Errorf("%w: created_at %s is more than %s in the future", ErrBadBundle, m.CreatedAt.UTC().Format(time.RFC3339), MaxCreatedAtSkew)
	}
	if !cleanText(m.Builder, 128) || !cleanText(m.Source, 128) {
		return fmt.Errorf("%w: builder/source", ErrBadBundle)
	}
	if len(m.Ecosystems) > MaxBundleEntries {
		return fmt.Errorf("%w: too many ecosystems", ErrBadBundle)
	}
	for _, e := range m.Ecosystems {
		if !cleanText(e, 64) || e == "" {
			return fmt.Errorf("%w: bad ecosystem name", ErrBadBundle)
		}
	}
	n := 2 + len(m.Files)
	if m.KEV != nil {
		n++
	}
	if m.EPSS != nil {
		n++
	}
	if n > MaxBundleEntries {
		return fmt.Errorf("%w: %d entries (max %d)", ErrBadBundle, n, MaxBundleEntries)
	}
	seen := map[string]bool{}
	check := func(f FileEntry, wantPrefix string) error {
		if !entryNameRe.MatchString(f.Name) || !strings.HasPrefix(f.Name, wantPrefix) {
			return fmt.Errorf("%w: manifest names %q", ErrBadBundle, safety.StripControl(f.Name))
		}
		if seen[f.Name] {
			return fmt.Errorf("%w: manifest lists %s twice", ErrBadBundle, f.Name)
		}
		seen[f.Name] = true
		if !sha256Re.MatchString(f.SHA256) {
			return fmt.Errorf("%w: %s: bad sha256", ErrBadBundle, f.Name)
		}
		if f.Bytes < 0 || f.Bytes > MaxBundleDecompressed || f.Records < 0 {
			return fmt.Errorf("%w: %s: bad size or record count", ErrBadBundle, f.Name)
		}
		return nil
	}
	for _, f := range m.Files {
		if err := check(f, "affected/"); err != nil {
			return err
		}
	}
	if m.KEV != nil {
		if err := check(*m.KEV, kevName); err != nil {
			return err
		}
		if m.KEV.Bytes > MaxFeedBytes {
			return fmt.Errorf("%w: kev.json over %d bytes", ErrBadBundle, MaxFeedBytes)
		}
	}
	if m.EPSS != nil {
		if err := check(*m.EPSS, epssName); err != nil {
			return err
		}
		if m.EPSS.Bytes > MaxFeedBytes {
			return fmt.Errorf("%w: epss.csv over %d bytes", ErrBadBundle, MaxFeedBytes)
		}
	}
	return nil
}

func cleanText(s string, max int) bool {
	return len(s) <= max && s == safety.StripControl(s) && !strings.ContainsAny(s, "\n\t")
}

// ---- keys ----

// GenerateKey returns a fresh ed25519 seed and its public key.
func GenerateKey() (seed []byte, pub ed25519.PublicKey, err error) {
	seed = make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, err
	}
	return seed, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), nil
}

// WriteKeyFile stores a seed at path with mode 0600, refusing to overwrite.
func WriteKeyFile(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return errors.New("key: bad seed length")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	_, werr := f.WriteString(seedPrefix + base64.StdEncoding.EncodeToString(seed) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// ReadKeyFile loads a seed written by WriteKeyFile.
func ReadKeyFile(path string) ([]byte, error) {
	b, err := readSmall(path, MaxSignatureBytes)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if !strings.HasPrefix(s, seedPrefix) {
		return nil, errors.New("read key: not a scnr bundle signing key")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, seedPrefix))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("read key: malformed seed")
	}
	return seed, nil
}

func readSmall(path string, max int64) ([]byte, error) {
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

// PublicKey derives the public key from a seed.
func PublicKey(seed []byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
}

// Sign returns the ed25519 signature over the exact manifest bytes.
func Sign(seed []byte, manifest []byte) []byte {
	return ed25519.Sign(ed25519.NewKeyFromSeed(seed), manifest)
}

// FormatTrustedKey renders a public key as "ed25519:<base64>" for scnr.yaml.
func FormatTrustedKey(pub ed25519.PublicKey) string {
	return keyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParseTrustedKey parses "ed25519:<base64>".
func ParseTrustedKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, keyPrefix) {
		return nil, fmt.Errorf("trusted key %q: want ed25519:<base64>", safety.StripControl(truncateStr(s, 40)))
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, keyPrefix))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trusted key: malformed ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParseTrustedKeys parses every entry, failing on the first bad one.
func ParseTrustedKeys(ss []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(ss))
	for _, s := range ss {
		k, err := ParseTrustedKey(s)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// KeyFingerprint is the first 32 hex characters of SHA-256 over the public
// key, as printed by keygen/verify and recorded in the audit row.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:32]
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// ---- reading ----

// BundleReader verifies and loads bundles.
type BundleReader struct {
	Keys            []ed25519.PublicKey
	MaxDecompressed int64
	// Store receives the load; nil for Verify-only use.
	Store    *store.Store
	Redactor *safety.Redactor
	// Now is the clock for the created_at checks (tests); nil means time.Now.
	Now func() time.Time
}

func (r *BundleReader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// LoadResult summarises a verified or loaded bundle.
type LoadResult struct {
	Manifest Manifest
	// Records is the number of affected rows staged (0 for Verify).
	Records int64
	KEV     int
	EPSS    int
	// BundleSHA256 is the digest of the bundle file as read.
	BundleSHA256 string
	// Signer is the fingerprint of the trusted key that verified the
	// manifest; empty when the bundle was accepted unsigned.
	Signer   string
	Unsigned bool
	// Downgrade is true when the bundle is older than the data it replaced
	// and was accepted with allowDowngrade.
	Downgrade bool
	// BytesRead counts decompressed bytes consumed, including on failure
	// (the untrusted-bundle invariant is asserted on it).
	BytesRead int64
}

// Verify checks the signature, structure and digests without touching the
// store.
func (r *BundleReader) Verify(ctx context.Context, path string, allowUnsigned bool) (LoadResult, error) {
	return r.walk(ctx, path, allowUnsigned, nil)
}

// Load verifies the bundle and replaces osv_affected (and kev/epss when the
// bundle carries them) in one transaction. Nothing is written until the
// signature verifies; nothing is kept unless every digest matches. A bundle
// whose created_at is older than the loaded osv-offline data is refused
// with ErrBundleOlder unless allowDowngrade is set (the caller gates that
// flag like allowUnsigned and audits it).
func (r *BundleReader) Load(ctx context.Context, path string, allowUnsigned, allowDowngrade bool) (LoadResult, error) {
	if r.Store == nil {
		return LoadResult{}, errors.New("bundle load: no store")
	}
	var load *store.OfflineLoad
	downgrade := false
	res, err := r.walk(ctx, path, allowUnsigned, func(ctx context.Context, m Manifest) (*store.OfflineLoad, error) {
		older, err := r.olderThanLoaded(ctx, m)
		if err != nil {
			return nil, err
		}
		if older && !allowDowngrade {
			return nil, fmt.Errorf("%w: %w", ErrBundleOlder, &safety.RefusalError{Code: safety.CodeBundleDowngrade, Target: path,
				Reason: "bundle created_at " + m.CreatedAt.UTC().Format(time.RFC3339) + " is older than the loaded osv-offline data; refusing without --allow-downgrade"})
		}
		downgrade = older
		l, err := r.Store.BeginOfflineLoad(ctx)
		load = l
		return l, err
	})
	if err != nil {
		if load != nil {
			load.Rollback() //nolint:errcheck // best effort; the load error is the real one
		}
		return res, err
	}
	res.Downgrade = downgrade
	if err := load.Commit(ctx, res.Manifest.CreatedAt.UTC().Format(time.RFC3339)); err != nil {
		return res, fmt.Errorf("bundle load: %w", err)
	}
	return res, nil
}

// olderThanLoaded reports whether m predates the osv-offline data in the
// store. The stored version is the RFC 3339 created_at Commit wrote; a
// missing or unparsable one means there is nothing to compare against.
func (r *BundleReader) olderThanLoaded(ctx context.Context, m Manifest) (bool, error) {
	metas, err := r.Store.VulnDBStatus(ctx)
	if err != nil {
		return false, fmt.Errorf("bundle load: %w", err)
	}
	for _, meta := range metas {
		if meta.Source != store.SourceOSVOffline || meta.UpdatedAt.IsZero() {
			continue
		}
		cur, err := time.Parse(time.RFC3339, meta.Version)
		if err != nil {
			return false, nil
		}
		return m.CreatedAt.Before(cur), nil
	}
	return false, nil
}

// untrusted builds the refusal for a signature failure.
func untrusted(path, reason string) error {
	return &safety.RefusalError{Code: safety.CodeBundleUntrusted, Target: path, Reason: reason}
}

// walk streams the bundle: manifest, signature, verify, then every data
// entry through the digest check and (when begin is set) the staging load.
func (r *BundleReader) walk(ctx context.Context, path string, allowUnsigned bool, begin func(context.Context, Manifest) (*store.OfflineLoad, error)) (res LoadResult, err error) {
	f, err := os.Open(path)
	if err != nil {
		return res, fmt.Errorf("bundle: %w", err)
	}
	defer f.Close()
	fileHash := sha256.New()
	gz, err := gzip.NewReader(bufio.NewReaderSize(io.TeeReader(f, fileHash), 64<<10))
	if err != nil {
		return res, fmt.Errorf("%w: not gzip: %v", ErrBadBundle, err)
	}
	defer gz.Close() //nolint:errcheck // bundle stream cleanup
	limit := r.MaxDecompressed
	if limit <= 0 {
		limit = MaxBundleDecompressed
	}
	counted := &safety.CountingReader{R: gz, N: &res.BytesRead, Limit: limit, Err: ErrBundleTooLarge}
	tr := tar.NewReader(counted)
	entries := 0
	next := func() (*tar.Header, error) {
		for {
			hdr, err := tr.Next()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, ErrBundleTooLarge) {
					return nil, err
				}
				return nil, fmt.Errorf("%w: tar: %v", ErrBadBundle, err)
			}
			entries++
			if entries > MaxBundleEntries {
				return nil, fmt.Errorf("%w: more than %d entries", ErrBadBundle, MaxBundleEntries)
			}
			if hdr.Typeflag == tar.TypeXGlobalHeader {
				continue
			}
			if hdr.Typeflag != tar.TypeReg {
				return nil, fmt.Errorf("%w: entry %q is not a regular file", ErrBadBundle, safety.StripControl(hdr.Name))
			}
			if !entryNameRe.MatchString(hdr.Name) {
				return nil, fmt.Errorf("%w: entry name %q not allowed", ErrBadBundle, safety.StripControl(truncateStr(hdr.Name, 80)))
			}
			return hdr, nil
		}
	}

	// 1. manifest.json: first entry, size-capped, bytes kept verbatim for
	// the signature check. Nothing in it is interpreted yet.
	hdr, err := next()
	if err != nil {
		return res, fmt.Errorf("%w: missing manifest.json", ErrBadBundle)
	}
	if hdr.Name != manifestName || hdr.Size > MaxManifestBytes {
		return res, fmt.Errorf("%w: first entry must be manifest.json (<= %d bytes)", ErrBadBundle, MaxManifestBytes)
	}
	manifestBytes, err := io.ReadAll(tr)
	if err != nil {
		return res, fmt.Errorf("%w: manifest.json: %v", ErrBadBundle, err)
	}

	// 2. manifest.sig: second entry. Verify before any other byte is read.
	hdr, err = next()
	var pending *tar.Header
	switch {
	case errors.Is(err, io.EOF):
		hdr = nil
	case err != nil:
		return res, err
	}
	if hdr != nil && hdr.Name == signatureName {
		if hdr.Size > MaxSignatureBytes {
			return res, untrusted(path, "manifest.sig over size cap")
		}
		sigB64, err := io.ReadAll(tr)
		if err != nil {
			return res, untrusted(path, "manifest.sig unreadable")
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
		if err != nil || len(sig) != ed25519.SignatureSize {
			return res, untrusted(path, "manifest.sig is not a base64 ed25519 signature")
		}
		for _, k := range r.Keys {
			if ed25519.Verify(k, manifestBytes, sig) {
				res.Signer = KeyFingerprint(k)
				break
			}
		}
		if res.Signer == "" {
			if len(r.Keys) == 0 {
				return res, untrusted(path, "no trusted keys configured (vulndb.trusted_keys in scnr.yaml)")
			}
			return res, untrusted(path, "signature does not verify against any trusted key")
		}
	} else {
		if !allowUnsigned {
			return res, untrusted(path, "bundle is unsigned (manifest.sig missing); refusing without --allow-unsigned")
		}
		res.Unsigned = true
		pending = hdr
	}

	// 3. Only now is the manifest interpreted.
	dec := json.NewDecoder(bytes.NewReader(manifestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res.Manifest); err != nil || dec.More() {
		return res, fmt.Errorf("%w: manifest.json: malformed", ErrBadBundle)
	}
	if err := res.Manifest.validate(r.now()); err != nil {
		return res, err
	}
	declared := res.Manifest.entries()
	seen := map[string]bool{}

	var load *store.OfflineLoad
	if begin != nil {
		if load, err = begin(ctx, res.Manifest); err != nil {
			return res, err
		}
	}

	// 4. Data entries: listed, sized, digested, decoded strictly.
	for {
		if pending != nil {
			hdr, pending = pending, nil
		} else {
			hdr, err = next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return res, err
			}
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if hdr.Name == manifestName || hdr.Name == signatureName {
			return res, fmt.Errorf("%w: duplicate %s", ErrBadBundle, hdr.Name)
		}
		entry, ok := declared[hdr.Name]
		if !ok {
			return res, fmt.Errorf("%w: entry %s not listed in manifest", ErrBadBundle, hdr.Name)
		}
		if seen[hdr.Name] {
			return res, fmt.Errorf("%w: entry %s appears twice", ErrBadBundle, hdr.Name)
		}
		seen[hdr.Name] = true
		if hdr.Size != entry.Bytes {
			return res, fmt.Errorf("%w: %s: size %d, manifest says %d", ErrBadBundle, hdr.Name, hdr.Size, entry.Bytes)
		}
		h := sha256.New()
		body := io.TeeReader(tr, h)
		switch hdr.Name {
		case kevName:
			kev, version, err := ParseKEV(body)
			if err != nil {
				return res, fmt.Errorf("%w: kev.json: %v", ErrBadBundle, err)
			}
			res.KEV = len(kev)
			if load != nil {
				if err := load.ReplaceKEV(ctx, kev, version); err != nil {
					return res, err
				}
			}
		case epssName:
			epss, version, err := ParseEPSS(body)
			if err != nil {
				return res, fmt.Errorf("%w: epss.csv: %v", ErrBadBundle, err)
			}
			res.EPSS = len(epss)
			if load != nil {
				if err := load.ReplaceEPSS(ctx, epss, version); err != nil {
					return res, err
				}
			}
		default:
			n, err := r.readAffected(ctx, hdr.Name, body, entry.Records, load)
			if err != nil {
				return res, err
			}
			res.Records += n
		}
		// Drain anything the parser left so the digest covers the whole entry.
		if _, err := io.Copy(io.Discard, body); err != nil {
			return res, fmt.Errorf("%w: %s: %v", ErrBadBundle, hdr.Name, err)
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != entry.SHA256 {
			return res, fmt.Errorf("%w: %s: sha256 mismatch", ErrBadBundle, hdr.Name)
		}
	}
	for name := range declared {
		if !seen[name] {
			return res, fmt.Errorf("%w: %s listed in manifest but missing", ErrBadBundle, name)
		}
	}
	// The tar end-of-archive marker has been read. Drain the rest of the
	// decompressed stream through the counting reader (so a trailing gzip
	// member cannot bypass the size cap) and refuse any data after the tar
	// end: padding or a second member is not part of the fixed shape.
	trailing, err := io.Copy(io.Discard, counted)
	if err != nil {
		if errors.Is(err, ErrBundleTooLarge) {
			return res, err
		}
		return res, fmt.Errorf("%w: trailer: %v", ErrBadBundle, err)
	}
	if trailing > 0 {
		return res, fmt.Errorf("%w: %d bytes of decompressed data after the tar end", ErrBadBundle, trailing)
	}
	if _, err := io.Copy(io.Discard, f); err != nil {
		return res, fmt.Errorf("bundle: %w", err)
	}
	res.BundleSHA256 = hex.EncodeToString(fileHash.Sum(nil))
	return res, nil
}

// readAffected streams one affected/*.jsonl entry: line cap, strict record
// decode, clean, stage, and an exact record count.
func (r *BundleReader) readAffected(ctx context.Context, name string, body io.Reader, want int64, load *store.OfflineLoad) (int64, error) {
	br := bufio.NewReaderSize(body, 64<<10)
	var n int64
	for {
		line, tooLong, rerr := adapter.ReadLine(br, MaxBundleLineBytes)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return n, fmt.Errorf("%w: %s: %v", ErrBadBundle, name, rerr)
		}
		if tooLong {
			return n, fmt.Errorf("%w: %s: line %d over %d bytes", ErrBadBundle, name, n+1, MaxBundleLineBytes)
		}
		if len(line) == 0 && errors.Is(rerr, io.EOF) {
			break // trailing newline
		}
		n++
		if n > want {
			return n, fmt.Errorf("%w: %s: more than %d records declared", ErrBadBundle, name, want)
		}
		rec, err := sca.DecodeRecord(line)
		if err != nil {
			return n, fmt.Errorf("%w: %s: line %d: %v", ErrBadBundle, name, n, err)
		}
		if load != nil {
			rec.Clean(r.Redactor)
			if err := load.Stage(ctx, rec.Row()); err != nil {
				return n, err
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
	}
	if n != want {
		return n, fmt.Errorf("%w: %s: %d records, manifest says %d", ErrBadBundle, name, n, want)
	}
	return n, nil
}
