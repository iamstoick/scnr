// Package imagetest builds synthetic container image archives for tests and
// the committed fixtures (testdata/image/gen). Nothing here touches a
// registry or daemon.
package imagetest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Entry is one tar entry. Typ defaults to a regular file; set Typ to
// tar.TypeSymlink/TypeLink/TypeDir for other kinds (Link is the target).
type Entry struct {
	Name    string
	Content string
	Typ     byte
	Link    string
	Mode    int64
}

var modTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// LayerTar writes entries into an uncompressed tar.
func LayerTar(entries []Entry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.Name, Mode: 0o644, ModTime: modTime, Typeflag: tar.TypeReg, Size: int64(len(e.Content))}
		if e.Mode != 0 {
			hdr.Mode = e.Mode
		}
		if e.Typ != 0 {
			hdr.Typeflag = e.Typ
			hdr.Linkname = e.Link
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.Content)); err != nil {
				panic(err)
			}
		}
	}
	tw.Close()
	return buf.Bytes()
}

// Gzip compresses b.
func Gzip(b []byte) []byte {
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(b)
	w.Close()
	return gz.Bytes()
}

// SHA256 returns the hex digest of b.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// DockerArchive assembles a `docker save`-style tarball: layers as
// <digest>/layer.tar, a config blob and manifest.json (written last, as
// docker does, so readers cannot rely on seeing it first). extra entries
// are appended verbatim (hostile names for tests).
func DockerArchive(layers [][]byte, repoTag string, extra ...Entry) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, ModTime: modTime, Typeflag: tar.TypeReg, Size: int64(len(b))})
		tw.Write(b)
	}
	var names []string
	for _, l := range layers {
		n := SHA256(l) + "/layer.tar"
		names = append(names, n)
		add(n, l)
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`)
	add(SHA256(cfg)+".json", cfg)
	for _, e := range extra {
		hdr := &tar.Header{Name: e.Name, Mode: 0o644, ModTime: modTime, Typeflag: tar.TypeReg, Size: int64(len(e.Content))}
		if e.Typ != 0 {
			hdr.Typeflag, hdr.Linkname, hdr.Size = e.Typ, e.Link, 0
		}
		tw.WriteHeader(hdr)
		if hdr.Typeflag == tar.TypeReg {
			tw.Write([]byte(e.Content))
		}
	}
	m, _ := json.Marshal([]map[string]any{{"Config": SHA256(cfg) + ".json", "RepoTags": []string{repoTag}, "Layers": names}})
	add("manifest.json", m)
	tw.Close()
	return buf.Bytes()
}

// OCILayout writes an OCI image layout directory with gzip layers.
func OCILayout(dir string, layers [][]byte) error {
	blobs := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		return err
	}
	var layerDescs []map[string]any
	for _, l := range layers {
		gz := Gzip(l)
		d := SHA256(gz)
		if err := os.WriteFile(filepath.Join(blobs, d), gz, 0o644); err != nil {
			return err
		}
		layerDescs = append(layerDescs, map[string]any{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + d, "size": len(gz)})
	}
	cfg := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`)
	if err := os.WriteFile(filepath.Join(blobs, SHA256(cfg)), cfg, 0o644); err != nil {
		return err
	}
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + SHA256(cfg), "size": len(cfg)}, "layers": layerDescs})
	if err := os.WriteFile(filepath.Join(blobs, SHA256(man)), man, 0o644); err != nil {
		return err
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []map[string]any{{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + SHA256(man), "size": len(man), "platform": map[string]string{"os": "linux", "architecture": "amd64"}}}})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644)
}

// Alpine fixture content shared by the committed fixture and tests.
const (
	APKInstalled = "C:Q1abc=\nP:musl\nV:1.2.4-r1\nA:x86_64\nS:400000\nI:600000\nT:the musl c library\nU:https://musl.libc.org/\nL:MIT\no:musl\nm:Timo Teräs <timo.teras@iki.fi>\nt:1700000000\nc:deadbeef\n\n" +
		"C:Q1def=\nP:busybox\nV:1.36.1-r15\nA:x86_64\no:busybox\nL:GPL-2.0-only\n\n" +
		"C:Q1ghi=\nP:libcrypto3\nV:3.1.4-r1\nA:x86_64\no:openssl\nL:Apache-2.0\n\n" +
		"C:Q1jkl=\nP:zlib\nV:1.2.13-r1\nA:x86_64\no:zlib\nL:Zlib\n\n"
	OSRelease = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.4\nPRETTY_NAME=\"Alpine Linux v3.18\"\nHOME_URL=\"https://alpinelinux.org/\"\n"
	Lockfile  = `{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20"},"node_modules/express":{"version":"4.18.2"}}}`
	// FakeSecret appears in the base layer and is whited out by the app layer.
	FakeSecret = "AKIAIOSFODNN7EXAMPLE"
)

// AlpineLayers returns the two layers of the small Alpine fixture: a base
// with apk db, os-release, a secret file and a symlink; an app layer with a
// lockfile and a whiteout removing the secret.
func AlpineLayers() [][]byte {
	base := LayerTar([]Entry{
		{Name: "etc/", Typ: tar.TypeDir},
		{Name: "etc/os-release", Content: OSRelease},
		{Name: "lib/apk/db/installed", Content: APKInstalled},
		{Name: "etc/secret.txt", Content: FakeSecret + "\n"},
		{Name: "usr/bin/sh", Typ: tar.TypeSymlink, Link: "/bin/busybox"},
	})
	app := LayerTar([]Entry{
		{Name: "app/package-lock.json", Content: Lockfile},
		{Name: "etc/.wh.secret.txt", Content: ""},
	})
	return [][]byte{base, app}
}
