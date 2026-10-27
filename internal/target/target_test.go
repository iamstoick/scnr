package target

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine/image/imagetest"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := f[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []net.IPAddr
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

func TestDetect(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.MkdirAll(filepath.Join(dir, "repo", ".git"), 0o755)
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o600)
	d := &Detector{Resolver: fakeResolver{"intranet.test": {"10.0.0.5"}, "public.test": {"203.0.113.1"}, "mixed.test": {"10.0.0.1", "203.0.113.2"}}}
	ctx := context.Background()
	cases := []struct {
		raw      string
		typ      domain.TargetType
		value    string
		public   bool
		hostname string
		wantErr  bool
	}{
		{"https://Example.TEST/path?x=1#frag", domain.TargetURL, "https://example.test/path?x=1", true, "example.test", false},
		{"http://intranet.test", domain.TargetURL, "http://intranet.test/", false, "intranet.test", false},
		{"aws://prod", domain.TargetCloud, "aws://prod", false, "", false},
		{"azure://my-sub", domain.TargetCloud, "azure://my-sub", false, "", false},
		{"azure://11111111-2222-3333-4444-555555555555", domain.TargetCloud, "azure://11111111-2222-3333-4444-555555555555", false, "", false},
		{filepath.Join(dir, "repo"), domain.TargetPath, filepath.Join(dir, "repo"), false, "", false},
		{filepath.Join(dir, "file.txt"), domain.TargetPath, filepath.Join(dir, "file.txt"), false, "", false},
		{"10.0.0.7", domain.TargetHost, "10.0.0.7", false, "10.0.0.7", false},
		{"203.0.113.9", domain.TargetHost, "203.0.113.9", true, "203.0.113.9", false},
		{"::1", domain.TargetHost, "::1", false, "::1", false},
		{"10.0.0.0/24", domain.TargetCIDR, "10.0.0.0/24", false, "", false},
		{"10.0.0.77/24", domain.TargetCIDR, "10.0.0.0/24", false, "", false},
		{"nginx:1.25", domain.TargetImage, "nginx:1.25", false, "", false},
		{"library/nginx", domain.TargetImage, "library/nginx", false, "", false},
		{"ghcr.io/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", domain.TargetImage, "", false, "", false},
		{"intranet.test", domain.TargetHost, "intranet.test", false, "intranet.test", false},
		{"public.test", domain.TargetHost, "public.test", true, "public.test", false},
		{"mixed.test", domain.TargetHost, "mixed.test", true, "mixed.test", false},
		{"nonexistent.test", "", "", false, "", true},
		{"", "", "", false, "", true},
		{"--flag", "", "", false, "", true},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := d.Detect(ctx, c.raw, "")
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != c.typ {
				t.Fatalf("type = %s, want %s", got.Type, c.typ)
			}
			if c.value != "" && got.Value != c.value {
				t.Fatalf("value = %q, want %q", got.Value, c.value)
			}
			if got.Public != c.public || got.Hostname != c.hostname {
				t.Fatalf("public=%v hostname=%q", got.Public, got.Hostname)
			}
		})
	}
	// Phase 3: local image archives are image targets with a source label;
	// a plain tar that is not an image stays a path; --type image on an
	// archive resolves to its absolute path; a registry ref has no label.
	tarPath, _ := filepath.Abs("../../testdata/image/alpine-small.tar")
	got, err := d.Detect(ctx, tarPath, "")
	if err != nil || got.Type != domain.TargetImage || got.Value != tarPath || got.Labels[ImageSourceLabel] != ImageSourceDockerTar {
		t.Fatalf("docker archive: %+v %v", got, err)
	}
	got, err = d.Detect(ctx, tarPath, domain.TargetImage)
	if err != nil || got.Type != domain.TargetImage || got.Value != tarPath || got.Labels[ImageSourceLabel] != ImageSourceDockerTar {
		t.Fatalf("--type image archive: %+v %v", got, err)
	}
	// Finding 5: a directory is never reclassified as an image from its
	// content; an OCI layout needs --type image and a valid oci-layout marker.
	oci, _ := filepath.Abs("../../testdata/image/oci-small")
	if got, err = d.Detect(ctx, oci, ""); err != nil || got.Type != domain.TargetPath {
		t.Fatalf("oci layout without --type must stay a path: %+v %v", got, err)
	}
	if got, err = d.Detect(ctx, oci, domain.TargetImage); err != nil || got.Type != domain.TargetImage || got.Value != oci || got.Labels[ImageSourceLabel] != ImageSourceOCILayout {
		t.Fatalf("--type image oci layout: %+v %v", got, err)
	}
	plain := filepath.Join(dir, "plain.tar")
	os.WriteFile(plain, imagetest.LayerTar([]imagetest.Entry{{Name: "README", Content: "hi"}}), 0o600)
	if got, err = d.Detect(ctx, plain, ""); err != nil || got.Type != domain.TargetPath {
		t.Fatalf("plain tar: %+v %v", got, err)
	}
	if _, err = d.Detect(ctx, plain, domain.TargetImage); err == nil || !strings.Contains(err.Error(), "not a container image archive") {
		t.Fatalf("--type image on a non-image tar must error, got %v", err)
	}
	if _, err = d.Detect(ctx, filepath.Join(dir, "file.txt"), domain.TargetImage); err == nil {
		t.Fatal("--type image on a text file must error")
	}
	if got, err = d.Detect(ctx, "alpine:3.18", domain.TargetImage); err != nil || got.Labels != nil || got.Value != "alpine:3.18" {
		t.Fatalf("registry ref: %+v %v", got, err)
	}
	// A directory with oci-layout but no index.json, or with a bogus
	// oci-layout marker, is not an image even with --type image.
	os.MkdirAll(filepath.Join(dir, "half"), 0o755)
	os.WriteFile(filepath.Join(dir, "half", "oci-layout"), []byte("{}"), 0o600)
	if got, _ = d.Detect(ctx, filepath.Join(dir, "half"), ""); got.Type != domain.TargetPath {
		t.Fatalf("half layout: %+v", got)
	}
	if _, err = d.Detect(ctx, filepath.Join(dir, "half"), domain.TargetImage); err == nil {
		t.Fatal("half layout with --type image accepted")
	}
	os.WriteFile(filepath.Join(dir, "half", "index.json"), []byte("{}"), 0o600)
	if _, err = d.Detect(ctx, filepath.Join(dir, "half"), domain.TargetImage); err == nil || !strings.Contains(err.Error(), "imageLayoutVersion") {
		t.Fatalf("bogus oci-layout marker accepted: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "half", "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600)
	if got, err = d.Detect(ctx, filepath.Join(dir, "half"), domain.TargetImage); err != nil || got.Labels[ImageSourceLabel] != ImageSourceOCILayout {
		t.Fatalf("valid marker: %+v %v", got, err)
	}
	// Probe: a git repository that also contains oci-layout + index.json is
	// still a repository.
	os.WriteFile(filepath.Join(dir, "repo", "main.go"), []byte("package main"), 0o600)
	os.WriteFile(filepath.Join(dir, "repo", "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600)
	os.WriteFile(filepath.Join(dir, "repo", "index.json"), []byte("{}"), 0o600)
	if got, err = d.Detect(ctx, filepath.Join(dir, "repo"), ""); err != nil || got.Type != domain.TargetPath || got.Labels["repo"] != "git" {
		t.Fatalf("repo with layout files reclassified: %+v %v", got, err)
	}
	// Ambiguous error type.
	_, err = d.Detect(ctx, "nonexistent.test", "")
	var amb *AmbiguousError
	if !errors.As(err, &amb) || !errors.Is(err, ErrAmbiguous) || len(amb.Candidates) == 0 {
		t.Fatalf("want AmbiguousError, got %v", err)
	}
	// Override.
	got, err = d.Detect(ctx, "nonexistent.test", domain.TargetHost)
	if err != nil || got.Type != domain.TargetHost || !got.Public {
		t.Fatalf("override: %+v %v (unresolvable hosts are treated as public)", got, err)
	}
	// repo label.
	got, _ = d.Detect(ctx, filepath.Join(dir, "repo"), "")
	if got.Labels["repo"] != "git" {
		t.Fatalf("repo label missing: %+v", got)
	}
	if _, err := ParseType("bogus"); err == nil {
		t.Fatal("bad --type accepted")
	}
}

func FuzzDetect(f *testing.F) {
	for _, s := range []string{"https://x.test", "10.0.0.1", "10.0.0.0/8", "nginx:1", "::1", "a/b@sha256:00", "", "-", "aws://x"} {
		f.Add(s)
	}
	d := &Detector{Resolver: fakeResolver{}}
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = d.Detect(context.Background(), raw, "")
	})
}
