package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/engine/image/imagetest"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/target"
)

const fixtureTar = "../../../testdata/image/alpine-small.tar"

func localTarget(p, src string) domain.Target {
	abs, _ := filepath.Abs(p)
	return domain.Target{Type: domain.TargetImage, Value: abs, Labels: map[string]string{SourceLabel: src}}
}

// fakeOSV answers the Alpine (by origin) and npm queries of the fixture.
func fakeOSV(t *testing.T) *httptest.Server {
	t.Helper()
	var seen []string
	t.Cleanup(func() {
		joined := strings.Join(seen, "\n")
		for _, want := range []string{"Alpine:v3.18 openssl 3.1.4-r1", "Alpine:v3.18 musl 1.2.4-r1", "npm lodash 4.17.20"} {
			if !strings.Contains(joined, want) {
				t.Errorf("OSV never asked about %q; queries:\n%s", want, joined)
			}
		}
		if strings.Contains(joined, "libcrypto3") {
			t.Error("OSV must be asked about the apk origin, not the binary package")
		}
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct{ Name, Ecosystem string } `json:"package"`
					Version string
				} `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				seen = append(seen, q.Package.Ecosystem+" "+q.Package.Name+" "+q.Version)
				results[i] = map[string]any{"vulns": []any{}}
				if q.Package.Name == "openssl" && q.Package.Ecosystem == "Alpine:v3.18" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": "CVE-2023-5363"}}}
				}
				if q.Package.Name == "lodash" {
					results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-p6mc-m468-83gw"}}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/CVE-2023-5363"):
			json.NewEncoder(w).Encode(map[string]any{"id": "CVE-2023-5363", "summary": "openssl: incorrect cipher key and IV length processing",
				"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
				"affected": []map[string]any{{"package": map[string]string{"ecosystem": "Alpine:v3.18", "name": "openssl"}, "ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "3.1.4-r2"}}}}}}})
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/GHSA-p6mc-m468-83gw"):
			json.NewEncoder(w).Encode(map[string]any{"id": "GHSA-p6mc-m468-83gw", "aliases": []string{"CVE-2020-8203"}, "summary": "Prototype Pollution in lodash",
				"affected": []map[string]any{{"package": map[string]string{"ecosystem": "npm", "name": "lodash"}, "ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}}}}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func newEngine(t *testing.T, osvURL string, client *http.Client) *Engine {
	t.Helper()
	s, err := sca.New(&sca.OSVClient{Base: osvURL, HTTP: client, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func run(t *testing.T, e *Engine, tg domain.Target, online bool) (map[string]domain.Finding, error) {
	t.Helper()
	out := map[string]domain.Finding{}
	err := e.Run(context.Background(), tg, engine.Options{Online: online}, func(f domain.Finding) error { out[f.RuleID] = f; return nil })
	return out, err
}

// Acceptance 3.3: the small alpine tar yields OS packages and OSV findings.
func TestFixtureTarAndOCILayout(t *testing.T) {
	srv := fakeOSV(t)
	defer srv.Close()
	e := newEngine(t, srv.URL, srv.Client())
	inv, err := e.Collect(fixtureTar)
	if err != nil {
		t.Fatal(err)
	}
	if inv.OS.ID != "alpine" || inv.OS.Ecosystem() != "Alpine:v3.18" || inv.OSPkgs != 4 || len(inv.Packages) != 6 || inv.Contents.Layers != 2 || inv.Contents.Source != "docker-archive" {
		t.Fatalf("%+v os=%+v", inv, inv.OS)
	}
	if _, ok := inv.Contents.Files["etc/secret.txt"]; ok {
		t.Fatal("whiteout not applied: secret.txt still present")
	}
	if _, ok := inv.Contents.Files["usr/bin/sh"]; ok {
		t.Fatal("symlink body must not be collected")
	}
	for _, src := range []struct{ path, label string }{{fixtureTar, SourceDockerTar}, {"../../../testdata/image/oci-small", SourceOCILayout}} {
		got, err := run(t, e, localTarget(src.path, src.label), true)
		if err != nil {
			t.Fatalf("%s: %v", src.path, err)
		}
		f, ok := got["sca.osv.CVE-2023-5363@pkg:apk/alpine/libcrypto3@3.1.4-r1"]
		if !ok {
			t.Fatalf("%s: findings %v", src.path, keys(got))
		}
		if f.Location != "lib/apk/db/installed" || f.Severity != domain.High || !strings.Contains(f.HowToFix, "3.1.4-r2") || !strings.Contains(f.Evidence[0].Redacted, "image: Alpine:v3.18 libcrypto3 3.1.4-r1") {
			t.Fatalf("%+v", f)
		}
		if _, ok := got["sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20"]; !ok {
			t.Fatalf("lockfile inside image not looked up: %v", keys(got))
		}
		if len(got) != 2 {
			t.Fatalf("unexpected extra findings: %v", keys(got))
		}
	}
	// Offline: skipped, not failed; no OSV traffic.
	_, err = run(t, newEngine(t, "http://127.0.0.1:1", nil), localTarget(fixtureTar, SourceDockerTar), false)
	var skip *engine.SkipError
	if !errors.As(err, &skip) || skip.Reason != "offline" {
		t.Fatalf("want offline skip, got %v", err)
	}
	// Target detection classifies the fixture as a local image.
	det := &target.Detector{}
	tg, err := det.Detect(context.Background(), fixtureTar, "")
	if err != nil || tg.Type != domain.TargetImage || tg.Labels[target.ImageSourceLabel] != SourceDockerTar || !IsLocal(tg) {
		t.Fatalf("detect: %+v %v", tg, err)
	}
	tg, err = det.Detect(context.Background(), "../../../testdata/image/oci-small", domain.TargetImage)
	if err != nil || tg.Type != domain.TargetImage || tg.Labels[target.ImageSourceLabel] != SourceOCILayout {
		t.Fatalf("detect oci with --type image: %+v %v", tg, err)
	}
	if tg, err = det.Detect(context.Background(), "../../../testdata/image/oci-small", ""); err != nil || tg.Type != domain.TargetPath {
		t.Fatalf("a directory is never auto-detected as an image: %+v %v", tg, err)
	}
	if target.ImageSourceLabel != SourceLabel || target.ImageSourceDockerTar != SourceDockerTar || target.ImageSourceOCILayout != SourceOCILayout {
		t.Fatal("target and image packages disagree on source labels")
	}
}

func keys(m map[string]domain.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Registry references are never pulled: skipped with a docker save hint.
func TestRegistryReferenceSkips(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1", nil)
	_, err := run(t, e, domain.Target{Type: domain.TargetImage, Value: "alpine:3.18"}, true)
	var skip *engine.SkipError
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "docker save alpine:3.18") {
		t.Fatalf("%v", err)
	}
	p, _ := e.Plan(context.Background(), domain.Target{Type: domain.TargetImage, Value: "alpine:3.18"}, engine.Options{Online: true})
	if !strings.Contains(p.Summary, "will be skipped") || p.Network {
		t.Fatalf("%+v", p)
	}
}

// Acceptance 3.3: an rpm image yields the informational handoff finding.
func TestRPMHandoffAndUnknownOS(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1", nil)
	rpm := imagetest.LayerTar([]imagetest.Entry{
		{Name: "etc/os-release", Content: "ID=fedora\nVERSION_ID=40\n"},
		{Name: "var/lib/rpm/rpmdb.sqlite", Content: "SQLite format 3\x00"},
	})
	p := filepath.Join(t.TempDir(), "rpm.tar")
	os.WriteFile(p, imagetest.DockerArchive([][]byte{rpm}, "fedora:40"), 0o600)
	got, err := run(t, e, localTarget(p, SourceDockerTar), true)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", keys(got), err)
	}
	if f := got["image.rpm-database-found"]; f.Severity != domain.Info || !strings.Contains(f.HowToFix, "trivy") {
		t.Fatalf("%+v", f)
	}
	// apk db without os-release: packages listed, OSV not asked, info finding.
	noOS := imagetest.LayerTar([]imagetest.Entry{{Name: "lib/apk/db/installed", Content: imagetest.APKInstalled}})
	p = filepath.Join(t.TempDir(), "noos.tar")
	os.WriteFile(p, imagetest.DockerArchive([][]byte{noOS}, "x:1"), 0o600)
	got, err = run(t, e, localTarget(p, SourceDockerTar), true)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", keys(got), err)
	}
	if _, ok := got["image.os-unknown"]; !ok {
		t.Fatalf("%v", keys(got))
	}
}

// Hostile archive: absolute and traversal names are ignored and reported;
// symlink and hardlink bodies are never read; a layer named by traversal in
// the manifest is dropped.
func TestHostileArchive(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1", nil)
	layer := imagetest.LayerTar([]imagetest.Entry{
		{Name: "../../../../etc/passwd", Content: "root:x:0:0\n"},
		{Name: "/etc/os-release", Content: "ID=alpine\nVERSION_ID=3.18.4\n"},
		{Name: "etc/os-release", Typ: tar.TypeSymlink, Link: "/etc/passwd"},
		{Name: "lib/apk/db/installed", Typ: tar.TypeLink, Link: "etc/passwd"},
		{Name: "lib/apk/db/../db/installed", Content: imagetest.APKInstalled}, // cleans to the db path, no traversal escape
		{Name: "a/..", Content: "x"},
	})
	p := filepath.Join(t.TempDir(), "hostile.tar")
	os.WriteFile(p, imagetest.DockerArchive([][]byte{layer}, "evil:1", imagetest.Entry{Name: "../../escape/layer.tar", Content: "x"}, imagetest.Entry{Name: "/abs.json", Content: "{}"}), 0o600)
	c, err := Open(p, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hostile != 5 {
		t.Fatalf("hostile count %d", c.Hostile)
	}
	if _, ok := c.Files["etc/os-release"]; ok {
		t.Fatal("symlink or absolute os-release was collected")
	}
	if _, ok := c.Files["lib/apk/db/installed"]; !ok {
		t.Fatal("cleaned in-tree path should be collected")
	}
	for k := range c.Files {
		if strings.HasPrefix(k, "/") || strings.Contains(k, "..") {
			t.Fatalf("hostile key %q collected", k)
		}
	}
	got, err := run(t, e, localTarget(p, SourceDockerTar), false)
	if err != nil {
		var skip *engine.SkipError
		if !errors.As(err, &skip) {
			t.Fatal(err)
		}
	}
	if f, ok := got["image.hostile-archive"]; !ok || f.Severity != domain.Medium || !strings.Contains(f.Evidence[0].Redacted, "5 entries") {
		t.Fatalf("%v %+v", keys(got), f)
	}
}

// Decompression bomb and entry flood: caps stop the walk and the engine
// reports image.too-large instead of exhausting memory.
func TestSizeCaps(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1", nil)
	e.Limits.LayerBytes = 64 << 10
	e.Limits.ImageBytes = 1 << 20
	big := imagetest.LayerTar([]imagetest.Entry{{Name: "etc/os-release", Content: strings.Repeat("A", 200<<10)}}) // 200 KiB of zeros-ish compresses to ~200 bytes
	dir := t.TempDir()
	if err := imagetest.OCILayout(dir, [][]byte{big}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, e.Limits); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	got, err := run(t, e, localTarget(dir, SourceOCILayout), true)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", keys(got), err)
	}
	if _, ok := got["image.too-large"]; !ok {
		t.Fatal(keys(got))
	}
	// Entry flood.
	e.Limits = DefaultLimits
	e.Limits.EntriesPerLayer = 10
	var entries []imagetest.Entry
	for i := 0; i < 50; i++ {
		entries = append(entries, imagetest.Entry{Name: "f" + strings.Repeat("x", i), Content: "y"})
	}
	p := filepath.Join(t.TempDir(), "flood.tar")
	os.WriteFile(p, imagetest.DockerArchive([][]byte{imagetest.LayerTar(entries)}, "flood:1"), 0o600)
	if _, err := Open(p, e.Limits); err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("flood accepted: %v", err)
	}
	// Collected-file caps: an oversized interesting file is skipped, not read.
	lim := DefaultLimits
	lim.FileBytes = 100
	huge := imagetest.LayerTar([]imagetest.Entry{{Name: "lib/apk/db/installed", Content: strings.Repeat("P:x\n", 100)}, {Name: "etc/os-release", Content: "ID=alpine\n"}})
	p = filepath.Join(t.TempDir(), "huge.tar")
	os.WriteFile(p, imagetest.DockerArchive([][]byte{huge}, "h:1"), 0o600)
	c, err := Open(p, lim)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Files["lib/apk/db/installed"]; ok {
		t.Fatal("oversized file collected")
	}
	if _, ok := c.Files["etc/os-release"]; !ok {
		t.Fatal("small file dropped")
	}
}

// zstd layers and bad digests are refused; gzip-wrapped docker archives work.
func TestUnsupportedAndGzippedArchives(t *testing.T) {
	e := newEngine(t, "http://127.0.0.1:1", nil)
	dir := t.TempDir()
	if err := imagetest.OCILayout(dir, imagetest.AlpineLayers()); err != nil {
		t.Fatal(err)
	}
	// Rewrite the manifest to claim zstd.
	idx, _ := os.ReadFile(filepath.Join(dir, "index.json"))
	var index struct {
		Manifests []struct{ Digest string } `json:"manifests"`
	}
	json.Unmarshal(idx, &index)
	mp := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(index.Manifests[0].Digest, "sha256:"))
	m, _ := os.ReadFile(mp)
	os.WriteFile(mp, bytes.ReplaceAll(m, []byte("tar+gzip"), []byte("tar+zstd")), 0o600)
	got, err := run(t, e, localTarget(dir, SourceOCILayout), true)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", keys(got), err)
	}
	if _, ok := got["image.unsupported-layer"]; !ok {
		t.Fatal(keys(got))
	}
	// A digest that is not 64 hex chars can never become a path.
	os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"manifests":[{"digest":"sha256:../../../../etc/passwd","mediaType":"application/vnd.oci.image.manifest.v1+json"}]}`), 0o600)
	if _, err := Open(dir, DefaultLimits); err == nil || !strings.Contains(err.Error(), "bad digest") {
		t.Fatalf("traversal digest accepted: %v", err)
	}
	// gzip-wrapped docker archive.
	raw, _ := os.ReadFile(fixtureTar)
	p := filepath.Join(t.TempDir(), "alpine.tar.gz")
	os.WriteFile(p, imagetest.Gzip(raw), 0o600)
	c, err := Open(p, DefaultLimits)
	if err != nil || len(c.Files) != 3 {
		t.Fatalf("%v %v", c, err)
	}
	// Not an image at all.
	p = filepath.Join(t.TempDir(), "plain.tar")
	os.WriteFile(p, imagetest.LayerTar([]imagetest.Entry{{Name: "README", Content: "hi"}}), 0o600)
	if _, err := Open(p, DefaultLimits); err == nil || !strings.Contains(err.Error(), "not a container image") {
		t.Fatalf("%v", err)
	}
}

func TestOSPackageParsers(t *testing.T) {
	pk := parseAPK([]byte(imagetest.APKInstalled), "Alpine:v3.18", apkDB)
	if len(pk) != 4 || pk[2].Name != "libcrypto3" || pk[2].Source != "openssl" || pk[0].Source != "" {
		t.Fatalf("%+v", pk)
	}
	dpkg := "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\nSource: glibc (2.36-9)\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: bash\nStatus: install ok installed\nVersion: 5.2.15-2\n"
	dp := parseDpkg([]byte(dpkg), "Debian:12", dpkgStatus)
	if len(dp) != 2 || dp[0].Source != "glibc" || dp[1].Name != "bash" {
		t.Fatalf("%+v", dp)
	}
	for in, want := range map[string]string{
		"ID=alpine\nVERSION_ID=3.18.4\n": "Alpine:v3.18", "ID=debian\nVERSION_ID=\"12\"\n": "Debian:12", "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.3 LTS (Jammy)\"\n": "Ubuntu:22.04:LTS",
		"ID=fedora\nVERSION_ID=40\n": "", "ID=alpine\n": "",
	} {
		if got := parseOSRelease([]byte(in)).Ecosystem(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// Finding 3: the image byte budget is enforced on bytes actually streamed
// (headers and PAX names included), not on the entries' declared sizes. A
// layer of Size-0 whiteouts with 512 KiB PAX names decompresses to several
// MiB from a few KiB of gzip; a 1 MiB image cap must refuse it instead of
// retaining the names.
func TestImageCapCountsStreamedBytes(t *testing.T) {
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	ltw := tar.NewWriter(gz)
	long := strings.Repeat("a", 512<<10)
	for i := 0; i < 10; i++ {
		if err := ltw.WriteHeader(&tar.Header{Name: long + fmt.Sprintf("%d/.wh.f", i), Typeflag: tar.TypeReg, Mode: 0o644, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
	}
	ltw.Close()
	gz.Close()
	if layer.Len() > 64<<10 {
		t.Fatalf("layer should compress small, got %d", layer.Len())
	}
	archive := imagetest.DockerArchive([][]byte{layer.Bytes()}, "wh:1")
	lim := DefaultLimits
	lim.ImageBytes = 1 << 20
	if _, err := openArchive(bytes.NewReader(archive), lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge from streamed-byte accounting, got %v", err)
	}
	lim.ImageBytes = DefaultLimits.ImageBytes
	lim.LayerBytes = 1 << 20
	if _, err := openArchive(bytes.NewReader(archive), lim); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("layer budget must count streamed bytes too, got %v", err)
	}
}

// Finding 3: whiteout entries are bounded: names over PATH_MAX and
// whiteouts past the per-layer cap are counted hostile, not retained; the
// image-wide entry cap spans layers.
func TestWhiteoutAndEntryCaps(t *testing.T) {
	entries := []imagetest.Entry{{Name: strings.Repeat("d/", 2500) + ".wh.x"}} // 5005 bytes
	for i := 0; i < maxWhiteoutsPerLayer+5; i++ {
		entries = append(entries, imagetest.Entry{Name: fmt.Sprintf("w/.wh.%d", i)})
	}
	entries = append(entries, imagetest.Entry{Name: "w/.wh..wh..opq"}, imagetest.Entry{Name: "etc/os-release", Content: "ID=alpine\n"})
	c, err := collectArchive(bytes.NewReader(imagetest.DockerArchive([][]byte{imagetest.LayerTar(entries)}, "wh:2")), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if c.hostile != 7 { // 1 long name + 5 excess whiteouts + 1 opaque past the cap
		t.Fatalf("hostile %d", c.hostile)
	}
	for _, l := range c.layers {
		if len(l.whiteout)+len(l.opaque) != maxWhiteoutsPerLayer {
			t.Fatalf("retained %d whiteouts", len(l.whiteout)+len(l.opaque))
		}
		if _, ok := l.files["etc/os-release"]; !ok {
			t.Fatal("regular file after the whiteouts must still be collected")
		}
	}
	lim := DefaultLimits
	lim.Entries = 20
	var small []imagetest.Entry
	for i := 0; i < 15; i++ {
		small = append(small, imagetest.Entry{Name: fmt.Sprintf("f%d", i), Content: "x"})
	}
	two := imagetest.DockerArchive([][]byte{imagetest.LayerTar(small), imagetest.LayerTar(small)}, "e:1")
	if _, err := openArchive(bytes.NewReader(two), lim); err == nil || !strings.Contains(err.Error(), "in total") {
		t.Fatalf("image-wide entry cap not enforced: %v", err)
	}
}

// Finding 4: non-archive blobs under blobs/sha256/ are retained under the
// same count cap as top-level JSON and under a total byte budget, so an
// archive of many small JSON blobs cannot pin memory.
func TestMetadataRetentionCaps(t *testing.T) {
	build := func(n int, blob []byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		add := func(name string, b []byte) {
			tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(b))})
			tw.Write(b)
		}
		add("manifest.json", []byte(`[{"Config":"c.json","Layers":[]}]`))
		for i := 0; i < n; i++ {
			add(fmt.Sprintf("blobs/sha256/%064x", i), blob)
		}
		tw.Close()
		return buf.Bytes()
	}
	c, err := collectArchive(bytes.NewReader(build(300, []byte(`{"x":"y"}`))), DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.meta) != maxMetaEntries {
		t.Fatalf("blob branch retained %d metadata entries, cap is %d", len(c.meta), maxMetaEntries)
	}
	lim := DefaultLimits
	lim.MetadataBytes = 16 << 10
	lim.MetadataTotalBytes = 64 << 10
	c, err = collectArchive(bytes.NewReader(build(300, []byte(`{"x":"`+strings.Repeat("A", 8<<10)+`"}`))), lim)
	if err != nil {
		t.Fatal(err)
	}
	if c.metaBytes > lim.MetadataTotalBytes || len(c.meta) > 8 {
		t.Fatalf("retained %d bytes in %d entries, budget %d", c.metaBytes, len(c.meta), lim.MetadataTotalBytes)
	}
	if _, ok := c.meta["manifest.json"]; !ok {
		t.Fatal("manifest must be kept")
	}
}

func FuzzArchive(f *testing.F) {
	raw, _ := os.ReadFile(fixtureTar)
	f.Add(raw)
	f.Add(imagetest.LayerTar([]imagetest.Entry{{Name: "../x", Content: "y"}}))
	f.Add(imagetest.LayerTar([]imagetest.Entry{{Name: strings.Repeat("d/", 2500) + ".wh.x"}, {Name: "a/.wh..wh..opq"}}))
	f.Add([]byte("not a tar"))
	f.Fuzz(func(t *testing.T, b []byte) {
		lim := DefaultLimits
		lim.ImageBytes, lim.LayerBytes = 1<<20, 1<<20
		_, _ = openArchive(bytes.NewReader(b), lim) // must never panic
		parseAPK(b, "Alpine:v3.18", apkDB)
		parseDpkg(b, "Debian:12", dpkgStatus)
		parseOSRelease(b)
	})
}
