package vulndb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
	"github.com/gerald/scnr/internal/vulndb/vulndbtest"
)

// rawEntry is a tar entry a test controls completely (hostile names,
// symlinks, wrong sizes).
type rawEntry struct {
	hdr  tar.Header
	body []byte
}

func reg(name string, body []byte) rawEntry {
	return rawEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}, body: body}
}

// packRaw gzips a tar of exactly these entries.
func packRaw(t *testing.T, entries []rawEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if err := tw.WriteHeader(&e.hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	f.Close()
	return path
}

func fileEntry(name string, body []byte, records int64) FileEntry {
	sum := sha256.Sum256(body)
	return FileEntry{Name: name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(body)), Records: records}
}

// lodashLines renders the fixture vuln as affected/npm.jsonl.
func lodashLines(t *testing.T) ([]byte, int64) {
	t.Helper()
	raw, _ := json.Marshal(vulndbtest.LodashVuln())
	var v sca.Vuln
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	recs := sca.RecordsFromVuln(&v, "npm")
	for _, r := range recs {
		b, _ := json.Marshal(r)
		buf.Write(append(b, '\n'))
	}
	return buf.Bytes(), int64(len(recs))
}

type bundleSpec struct {
	files    map[string][]byte // name -> body
	records  map[string]int64  // name -> declared record count (default: line count)
	kev      []byte
	epss     []byte
	seed     []byte // nil: unsigned
	tamper   func(m *Manifest)
	extra    []rawEntry // appended after the declared entries
	created  time.Time
	sigBytes []byte // overrides the signature body
}

// makeBundle writes a well-formed bundle from spec (then applies tamper).
func makeBundle(t *testing.T, s bundleSpec) string {
	t.Helper()
	m := Manifest{SchemaVersion: 1, CreatedAt: s.created, Builder: "scnr test", Source: "osv.dev"}
	if m.CreatedAt.IsZero() {
		m.CreatedAt = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	}
	var names []string
	for n := range s.files {
		names = append(names, n)
	}
	sortStrings(names)
	var data []rawEntry
	for _, n := range names {
		body := s.files[n]
		recs, ok := s.records[n]
		if !ok {
			recs = int64(bytes.Count(body, []byte("\n")))
		}
		m.Files = append(m.Files, fileEntry(n, body, recs))
		m.Ecosystems = append(m.Ecosystems, strings.TrimSuffix(strings.TrimPrefix(n, "affected/"), ".jsonl"))
		data = append(data, reg(n, body))
	}
	if s.kev != nil {
		fe := fileEntry(kevName, s.kev, 0)
		m.KEV = &fe
		data = append(data, reg(kevName, s.kev))
	}
	if s.epss != nil {
		fe := fileEntry(epssName, s.epss, 0)
		m.EPSS = &fe
		data = append(data, reg(epssName, s.epss))
	}
	if s.tamper != nil {
		s.tamper(&m)
	}
	mb, _ := json.Marshal(m)
	entries := []rawEntry{reg(manifestName, mb)}
	if s.seed != nil {
		sig := s.sigBytes
		if sig == nil {
			sig = []byte(base64.StdEncoding.EncodeToString(Sign(s.seed, mb)) + "\n")
		}
		entries = append(entries, reg(signatureName, sig))
	}
	entries = append(entries, data...)
	entries = append(entries, s.extra...)
	return packRaw(t, entries)
}

func sortStrings(ss []string) {
	for i := range ss {
		for j := i + 1; j < len(ss); j++ {
			if ss[j] < ss[i] {
				ss[i], ss[j] = ss[j], ss[i]
			}
		}
	}
}

func testKey(t *testing.T) ([]byte, *BundleReader, *store.Store) {
	t.Helper()
	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// Fixed clock after every fixture date, so bundles dated 2026/2027 are
	// not "in the future" (TestBundleFutureCreatedAt sets its own).
	return seed, &BundleReader{Keys: []ed25519.PublicKey{pub}, Store: st, Redactor: safety.NewRedactor(), Now: func() time.Time { return testClock }}, st
}

var testClock = time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

// An older bundle than the loaded data is refused (downgrade/replay) and
// audited as a refusal by the CLI; the same date reloads; --allow-downgrade
// accepts it and says so in the result.
func TestBundleRefusesDowngrade(t *testing.T) {
	seed, rd, st := testKey(t)
	lines, _ := lodashLines(t)
	ctx := context.Background()
	newer := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed, created: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
	older := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed, created: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	// An empty store has nothing to downgrade from.
	if res, err := rd.Load(ctx, older, false, false); err != nil || res.Downgrade {
		t.Fatalf("first load: %+v %v", res, err)
	}
	if _, err := rd.Load(ctx, newer, false, false); err != nil {
		t.Fatal(err)
	}
	_, err := rd.Load(ctx, older, false, false)
	var ref *safety.RefusalError
	if !errors.Is(err, ErrBundleOlder) || !errors.As(err, &ref) || ref.Code != safety.CodeBundleDowngrade {
		t.Fatalf("want ErrBundleOlder refusal, got %v", err)
	}
	if n, version := offlineRows(t, st); n != 1 || version != "2026-11-01T00:00:00Z" {
		t.Fatalf("store changed by refused downgrade: %d %q", n, version)
	}
	// Verify-only never consults the store, so it still reports the bundle.
	if _, err := rd.Verify(ctx, older, false); err != nil {
		t.Fatalf("verify older: %v", err)
	}
	// Same created_at is a reload, not a downgrade.
	if res, err := rd.Load(ctx, newer, false, false); err != nil || res.Downgrade {
		t.Fatalf("reload same date: %+v %v", res, err)
	}
	res, err := rd.Load(ctx, older, false, true)
	if err != nil || !res.Downgrade {
		t.Fatalf("allowDowngrade: %+v %v", res, err)
	}
	if _, version := offlineRows(t, st); version != "2026-10-01T00:00:00Z" {
		t.Fatalf("downgrade not applied: %q", version)
	}
}

// created_at more than 24h ahead of the clock is a bad bundle: it could
// otherwise block every later real bundle as a downgrade.
func TestBundleFutureCreatedAt(t *testing.T) {
	seed, rd, _ := testKey(t)
	lines, _ := lodashLines(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	rd.Now = func() time.Time { return now }
	within := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed, created: now.Add(23 * time.Hour)})
	if _, err := rd.Verify(ctx, within, false); err != nil {
		t.Fatalf("23h ahead is clock skew, not a bad bundle: %v", err)
	}
	future := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed, created: now.Add(25 * time.Hour)})
	if _, err := rd.Load(ctx, future, false, false); !errors.Is(err, ErrBadBundle) || !strings.Contains(err.Error(), "future") {
		t.Fatalf("want future created_at refused, got %v", err)
	}
}

// Decompressed data after the tar end (a second gzip member, padding) is a
// bad bundle, and it is counted against the size cap while being drained.
func TestBundleTrailingGzipMember(t *testing.T) {
	seed, rd, st := testKey(t)
	lines, _ := lodashLines(t)
	ctx := context.Background()
	good := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed})
	base, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	appendMember := func(t *testing.T, payload []byte) string {
		t.Helper()
		var buf bytes.Buffer
		buf.Write(base)
		gz := gzip.NewWriter(&buf)
		gz.Write(payload)
		gz.Close()
		p := filepath.Join(t.TempDir(), "trailing.tar.gz")
		if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	small := appendMember(t, []byte("extra"))
	if _, err := rd.Load(ctx, small, false, false); !errors.Is(err, ErrBadBundle) || !strings.Contains(err.Error(), "after the tar end") {
		t.Fatalf("trailing member accepted: %v", err)
	}
	if n, _ := offlineRows(t, st); n != 0 {
		t.Fatal("rolled back load left rows")
	}
	// A bomb in the trailing member hits the cap, not the disk.
	bomb := appendMember(t, make([]byte, 4<<20))
	rd.MaxDecompressed = 1 << 20
	res, err := rd.Load(ctx, bomb, false, false)
	if !errors.Is(err, ErrBundleTooLarge) {
		t.Fatalf("want size cap on the trailing member, got %v", err)
	}
	if res.BytesRead > rd.MaxDecompressed+64<<10 {
		t.Fatalf("read %d bytes past a %d cap", res.BytesRead, rd.MaxDecompressed)
	}
	rd.MaxDecompressed = 0
	if _, err := rd.Load(ctx, good, false, false); err != nil {
		t.Fatalf("well-formed bundle must still load: %v", err)
	}
}

func offlineRows(t *testing.T, st *store.Store) (int, string) {
	t.Helper()
	n, err := st.OSVAffectedCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metas, _ := st.VulnDBStatus(context.Background())
	for _, m := range metas {
		if m.Source == store.SourceOSVOffline {
			return n, m.Version
		}
	}
	return n, ""
}

func TestBundleRoundTrip(t *testing.T) {
	seed, rd, st := testKey(t)
	lines, nrec := lodashLines(t)
	kev, _ := os.ReadFile("../../testdata/vulndb/kev.json")
	epss, _ := os.ReadFile("../../testdata/vulndb/epss.csv")
	path := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, kev: kev, epss: epss, seed: seed})
	ctx := context.Background()

	v, err := rd.Verify(ctx, path, false)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Signer != KeyFingerprint(PublicKey(seed)) || v.Unsigned || len(v.BundleSHA256) != 64 || v.Manifest.Ecosystems[0] != "npm" {
		t.Fatalf("verify result: %+v", v)
	}
	if n, _ := offlineRows(t, st); n != 0 {
		t.Fatal("verify must not load")
	}
	res, err := rd.Load(ctx, path, false, false)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if res.Records != nrec || res.KEV != 2 || res.EPSS != 3 || res.BundleSHA256 != v.BundleSHA256 {
		t.Fatalf("load result: %+v", res)
	}
	n, version := offlineRows(t, st)
	if n != 1 || version != "2026-10-10T00:00:00Z" {
		t.Fatalf("rows %d version %q", n, version)
	}
	rows, err := st.AffectedFor(ctx, "npm", "lodash")
	if err != nil || len(rows) != 1 {
		t.Fatalf("AffectedFor: %v %v", rows, err)
	}
	rec, err := sca.DecodeRecord(rows[0].Body)
	if err != nil || len(rec.Ranges) != 2 || rec.Summary != "Prototype Pollution in lodash" || rec.CWE[0] != "CWE-1321" {
		t.Fatalf("stored record: %+v %v", rec, err)
	}
	if ok, _ := st.LookupKEV(ctx, "CVE-2021-44228"); !ok {
		t.Fatal("kev from bundle not loaded")
	}
	// Reloading replaces rather than merges, and bumps the version.
	path2 := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed, created: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := rd.Load(ctx, path2, false, false); err != nil {
		t.Fatal(err)
	}
	if n, version := offlineRows(t, st); n != 1 || version != "2026-11-01T00:00:00Z" {
		t.Fatalf("after reload: rows %d version %q", n, version)
	}
}

// A1: a bad signature stops the reader before the third entry is touched.
func TestBundleUntrustedStopsAtManifest(t *testing.T) {
	seed, rd, st := testKey(t)
	otherSeed, _, _ := GenerateKey()
	// Third entry is garbage that would fail parsing if it were ever read.
	hostile := []byte("{this is not json\x00\x01" + strings.Repeat("x", 4096))
	path := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": hostile}, records: map[string]int64{"affected/npm.jsonl": 1}, seed: otherSeed})
	res, err := rd.Load(context.Background(), path, false, false)
	var ref *safety.RefusalError
	if !errors.As(err, &ref) || ref.Code != safety.CodeBundleUntrusted {
		t.Fatalf("want E_BUNDLE_UNTRUSTED, got %v", err)
	}
	if strings.Contains(err.Error(), "json") || errors.Is(err, ErrBadBundle) {
		t.Fatalf("a parse error leaked before the signature check: %v", err)
	}
	// Decompressed bytes consumed: two 512-byte headers, the padded manifest
	// and the signature body. Never into the third entry's header.
	manifestSize := int64(0)
	{
		f, _ := os.Open(path)
		gz, _ := gzip.NewReader(f)
		tr := tar.NewReader(gz)
		h, _ := tr.Next()
		manifestSize = h.Size
		f.Close()
	}
	pad := func(n int64) int64 { return (n + 511) / 512 * 512 }
	if max := 1024 + pad(manifestSize) + 512; res.BytesRead > max || res.BytesRead == 0 {
		t.Fatalf("read %d decompressed bytes, max %d", res.BytesRead, max)
	}
	if n, _ := offlineRows(t, st); n != 0 {
		t.Fatal("untrusted bundle changed the store")
	}
	// Same bundle correctly signed but no keys configured: still untrusted.
	good := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": hostile}, records: map[string]int64{"affected/npm.jsonl": 1}, seed: seed})
	noKeys := &BundleReader{Store: st}
	if _, err := noKeys.Load(context.Background(), good, false, false); !errors.As(err, &ref) || ref.Code != safety.CodeBundleUntrusted {
		t.Fatalf("no trusted keys: %v", err)
	}
	// Signature body that is not base64/ed25519-sized.
	bad := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": hostile}, records: map[string]int64{"affected/npm.jsonl": 1}, seed: seed, sigBytes: []byte("not-a-signature\n")})
	if _, err := rd.Load(context.Background(), bad, false, false); !errors.As(err, &ref) || ref.Code != safety.CodeBundleUntrusted {
		t.Fatalf("malformed signature: %v", err)
	}
}

// A2: a digest mismatch in the last file leaves the previous load intact.
func TestBundleDigestMismatchRollsBack(t *testing.T) {
	seed, rd, st := testKey(t)
	lines, _ := lodashLines(t)
	ctx := context.Background()
	good := makeBundle(t, bundleSpec{files: map[string][]byte{"affected/npm.jsonl": lines}, seed: seed})
	if _, err := rd.Load(ctx, good, false, false); err != nil {
		t.Fatal(err)
	}
	before, versionBefore := offlineRows(t, st)
	kevBefore, _ := st.VulnDBStatus(ctx)

	// Second bundle: two files, the last one's declared digest is wrong, and
	// it carries a KEV file that must not land either.
	extraRec := `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"Go","name":"example.com/x","versions":["v1.0.0"]}` + "\n"
	kev, _ := os.ReadFile("../../testdata/vulndb/kev.json")
	bad := makeBundle(t, bundleSpec{
		files: map[string][]byte{"affected/npm.jsonl": lines, "affected/go.jsonl": []byte(extraRec)}, kev: kev, seed: seed,
		created: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		tamper: func(m *Manifest) {
			last := &m.Files[len(m.Files)-1]
			last.SHA256 = strings.Repeat("0", 64)
		},
	})
	_, err := rd.Load(ctx, bad, false, false)
	if !errors.Is(err, ErrBadBundle) || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want digest mismatch, got %v", err)
	}
	after, versionAfter := offlineRows(t, st)
	if after != before || versionAfter != versionBefore {
		t.Fatalf("store changed: rows %d->%d version %q->%q", before, after, versionBefore, versionAfter)
	}
	kevAfter, _ := st.VulnDBStatus(ctx)
	if kevAfter[0].Rows != kevBefore[0].Rows || kevAfter[0].UpdatedAt != kevBefore[0].UpdatedAt {
		t.Fatalf("kev changed by a rolled-back load: %+v -> %+v", kevBefore[0], kevAfter[0])
	}
	// The store still works after the rollback (no dangling staging table).
	if _, err := rd.Load(ctx, good, false, false); err != nil {
		t.Fatalf("reload after rollback: %v", err)
	}
}

// A3: entry grammar and caps are hard errors, never skips.
func TestBundleHostileEntries(t *testing.T) {
	seed, rd, st := testKey(t)
	lines, _ := lodashLines(t)
	npm := map[string][]byte{"affected/npm.jsonl": lines}
	one := `{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"Go","name":"example.com/x","versions":["v1.0.0"]}` + "\n"
	manyFiles := map[string][]byte{}
	for i := 0; i < 63; i++ { // 63 files + manifest + sig = 65 entries
		manyFiles[fmt.Sprintf("affected/eco%02d.jsonl", i)] = []byte(one)
	}
	longLine := []byte(`{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"Go","name":"` + strings.Repeat("a", MaxBundleLineBytes) + `"}` + "\n")
	cases := []struct {
		name    string
		spec    bundleSpec
		maxDec  int64
		wantErr string
	}{
		{"symlink entry", bundleSpec{files: npm, seed: seed, extra: []rawEntry{{hdr: tar.Header{Name: "kev.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}}}, 0, "not a regular file"},
		{"hardlink entry", bundleSpec{files: npm, seed: seed, extra: []rawEntry{{hdr: tar.Header{Name: "epss.csv", Typeflag: tar.TypeLink, Linkname: "manifest.json"}}}}, 0, "not a regular file"},
		{"directory entry", bundleSpec{files: npm, seed: seed, extra: []rawEntry{{hdr: tar.Header{Name: "affected/", Typeflag: tar.TypeDir}}}}, 0, "not a regular file"},
		{"traversal ../x", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("../x", []byte("x"))}}, 0, "not allowed"},
		{"traversal affected/../kev.json", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("affected/../kev.json", []byte("{}"))}}, 0, "not allowed"},
		{"absolute name", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("/etc/passwd", []byte("x"))}}, 0, "not allowed"},
		{"uppercase ecosystem file", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("affected/NPM.jsonl", []byte(one))}}, 0, "not allowed"},
		{"65th entry", bundleSpec{files: manyFiles, seed: seed}, 0, "entries"},
		{"line over 1 MiB", bundleSpec{files: map[string][]byte{"affected/go.jsonl": longLine}, records: map[string]int64{"affected/go.jsonl": 1}, seed: seed}, 0, "over"},
		{"decompressed over cap", bundleSpec{files: map[string][]byte{"affected/go.jsonl": bytes.Repeat([]byte{0}, 2<<20)}, records: map[string]int64{"affected/go.jsonl": 1}, seed: seed}, 1 << 20, "decompressed size over cap"},
		{"records one too few", bundleSpec{files: npm, records: map[string]int64{"affected/npm.jsonl": 2}, seed: seed}, 0, "manifest says 2"},
		{"records one too many", bundleSpec{files: npm, records: map[string]int64{"affected/npm.jsonl": 0}, seed: seed}, 0, "more than 0 records"},
		{"entry not in manifest", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("affected/go.jsonl", []byte(one))}}, 0, "not listed"},
		{"size differs from manifest", bundleSpec{files: npm, seed: seed, tamper: func(m *Manifest) { m.Files[0].Bytes++ }}, 0, "size"},
		{"unknown record field", bundleSpec{files: map[string][]byte{"affected/go.jsonl": []byte(`{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"Go","name":"x","evil":1}` + "\n")}, seed: seed}, 0, "unknown field"},
		{"record with control chars in name", bundleSpec{files: map[string][]byte{"affected/go.jsonl": []byte(`{"id":"GHSA-aaaa-bbbb-cccc","ecosystem":"Go","name":"x\u0007y"}` + "\n")}, seed: seed}, 0, "bad name"},
		{"missing listed file", bundleSpec{files: npm, seed: seed, tamper: func(m *Manifest) {
			m.Files = append(m.Files, FileEntry{Name: "affected/go.jsonl", SHA256: strings.Repeat("a", 64)})
		}}, 0, "missing"},
		{"schema version", bundleSpec{files: npm, seed: seed, tamper: func(m *Manifest) { m.SchemaVersion = 2 }}, 0, "schema_version"},
		{"duplicate manifest entry", bundleSpec{files: npm, seed: seed, extra: []rawEntry{reg("manifest.json", []byte("{}"))}}, 0, "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := makeBundle(t, tc.spec)
			r := *rd
			r.MaxDecompressed = tc.maxDec
			_, err := r.Load(context.Background(), path, false, false)
			if err == nil || !errors.Is(err, ErrBadBundle) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want ErrBadBundle containing %q, got %v", tc.wantErr, err)
			}
			if n, _ := offlineRows(t, st); n != 0 {
				t.Fatal("hostile bundle changed the store")
			}
		})
	}

	// Unsigned: refused by default, accepted only with allowUnsigned.
	unsigned := makeBundle(t, bundleSpec{files: npm})
	var ref *safety.RefusalError
	if _, err := rd.Load(context.Background(), unsigned, false, false); !errors.As(err, &ref) || ref.Code != safety.CodeBundleUntrusted {
		t.Fatalf("unsigned should be refused: %v", err)
	}
	res, err := rd.Load(context.Background(), unsigned, true, false)
	if err != nil || !res.Unsigned || res.Signer != "" || res.Records != 1 {
		t.Fatalf("unsigned with allowUnsigned: %+v %v", res, err)
	}
	// Not a gzip file at all.
	plain := filepath.Join(t.TempDir(), "x.tar.gz")
	os.WriteFile(plain, []byte("hello"), 0o600)
	if _, err := rd.Load(context.Background(), plain, false, false); !errors.Is(err, ErrBadBundle) {
		t.Fatalf("plain file: %v", err)
	}
}

// A5: the builder reaches only the GCS host through the endpoint client; a
// redirect elsewhere is refused.
func TestBuilderEndpointAllowlist(t *testing.T) {
	seed, rd, st := testKey(t)
	zips := map[string][]byte{"npm": vulndbtest.Zip(t, vulndbtest.LodashVuln(), map[string]any{"id": "NOT-FOR-NPM", "affected": []map[string]any{{"package": map[string]string{"ecosystem": "PyPI", "name": "requests"}}}})}
	srv := vulndbtest.GCSServer(t, zips, "")
	u, _ := url.Parse(srv.URL)
	client, err := safety.NewEndpointClient([]string{u.Hostname()}, safety.HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	b := &Builder{HTTP: client, Out: out, Ecosystems: []string{"npm"}, SignSeed: seed, Base: srv.URL, Builder: "scnr test",
		Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }}
	res, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(res.Path) != "scnr-osv-20261010.tar.gz" || len(res.Manifest.Files) != 1 || res.Manifest.Files[0].Records != 1 || res.Manifest.Files[0].Name != "affected/npm.jsonl" {
		t.Fatalf("build: %+v", res)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 1 {
		t.Fatalf("build dir should hold only the bundle: %v", entries)
	}
	ctx := context.Background()
	loaded, err := rd.Load(ctx, res.Path, false, false)
	if err != nil || loaded.Records != 1 || loaded.Signer != KeyFingerprint(PublicKey(seed)) {
		t.Fatalf("load built bundle: %+v %v", loaded, err)
	}
	if n, _ := offlineRows(t, st); n != 1 {
		t.Fatal("rows")
	}

	// Redirect off the allowlist (a different loopback address, private but
	// not declared): refused before any dial.
	redir := vulndbtest.GCSServer(t, nil, "http://127.0.0.2:1/npm/all.zip")
	b2 := &Builder{HTTP: client, Out: t.TempDir(), Ecosystems: []string{"npm"}, Base: redir.URL}
	_, err = b2.Build(ctx)
	if _, ok := safety.AsRedirectOutOfScope(err); !ok {
		t.Fatalf("want RedirectOutOfScopeError, got %v", err)
	}
	// A host that is not on the allowlist at all is refused outright.
	b3 := &Builder{HTTP: client, Out: t.TempDir(), Ecosystems: []string{"npm"}, Base: "http://127.0.0.2:1"}
	if _, err := b3.Build(ctx); err == nil || !strings.Contains(err.Error(), safety.CodeScopeNotAllowed) {
		t.Fatalf("undeclared host: %v", err)
	}
	// Bad ecosystem names never reach the network.
	for _, eco := range []string{"../x", "npm/x", "", strings.Repeat("a", 40)} {
		if _, err := (&Builder{HTTP: client, Out: t.TempDir(), Ecosystems: []string{eco}, Base: srv.URL}).Build(ctx); err == nil {
			t.Fatalf("ecosystem %q accepted", eco)
		}
	}
}

func TestKeys(t *testing.T) {
	seed, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := FormatTrustedKey(pub)
	if !strings.HasPrefix(s, "ed25519:") {
		t.Fatal(s)
	}
	back, err := ParseTrustedKey(s)
	if err != nil || !bytes.Equal(back, pub) {
		t.Fatalf("roundtrip: %v", err)
	}
	for _, bad := range []string{"", "ed25519:", "ed25519:!!!", "rsa:" + s[8:], "ed25519:" + base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParseTrustedKey(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	path := filepath.Join(t.TempDir(), "k")
	if err := WriteKeyFile(path, seed); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := WriteKeyFile(path, seed); err == nil {
		t.Fatal("overwrote an existing key")
	}
	got, err := ReadKeyFile(path)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("read key: %v", err)
	}
	if len(KeyFingerprint(pub)) != 32 || KeyFingerprint(pub) != KeyFingerprint(PublicKey(seed)) {
		t.Fatal("fingerprint")
	}
	if StaleAfterFor(store.SourceOSVOffline) != OfflineStaleAfter || StaleAfterFor("kev") != StaleAfter {
		t.Fatal("stale thresholds")
	}
}

// A symlink planted at the bundle's output name is refused and its target
// is untouched; the work dir is cleaned up and nothing else lands in --out.
func TestBuilderRefusesSymlinkOut(t *testing.T) {
	seed, _, _ := testKey(t)
	srv := vulndbtest.GCSServer(t, map[string][]byte{"npm": vulndbtest.Zip(t, vulndbtest.LodashVuln())}, "")
	u, _ := url.Parse(srv.URL)
	client, err := safety.NewEndpointClient([]string{u.Hostname()}, safety.HTTPOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(out, "scnr-osv-20261010.tar.gz")
	if err := os.Symlink(victim, dst); err != nil {
		t.Fatal(err)
	}
	b := &Builder{HTTP: client, Out: out, Ecosystems: []string{"npm"}, SignSeed: seed, Base: srv.URL,
		Now: func() time.Time { return time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) }}
	if _, err := b.Build(context.Background()); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("want symlink refusal, got %v", err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "precious" {
		t.Fatalf("symlink target overwritten: %q", got)
	}
	if st, err := os.Lstat(dst); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("planted link replaced: %v %v", st, err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 1 {
		t.Fatalf("out dir should hold only the planted link: %v", entries)
	}
	// A FIFO or other non-regular file at the name is refused too.
	os.Remove(dst)
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Build(context.Background()); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want non-regular refusal, got %v", err)
	}
	// An existing regular bundle from the same day is replaced in place.
	os.Remove(dst)
	os.WriteFile(dst, []byte("old"), 0o644)
	res, err := b.Build(context.Background())
	if err != nil || res.Path != dst {
		t.Fatalf("rebuild over a regular file: %+v %v", res, err)
	}
	if st, _ := os.Stat(dst); st.Size() <= 3 {
		t.Fatal("bundle not written")
	}
}
