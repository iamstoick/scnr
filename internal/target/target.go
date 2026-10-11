// Package target detects what kind of thing a user pointed scnr at and
// normalises it (Section 5.1).
package target

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/safety"
)

// ErrAmbiguous is returned when no rule matches.
var ErrAmbiguous = errors.New("E_TARGET_AMBIGUOUS")

// ErrURLCredentials is returned for URL targets carrying user:password@.
// The message deliberately omits the input so the credential is never
// echoed to stderr, logs or the audit trail.
var ErrURLCredentials = errors.New("credentials in the target URL are not supported; remove the user:password@ part (authenticated scanning via a header/cookie option is planned)")

// AmbiguousError lists what the input could have been.
type AmbiguousError struct {
	Raw        string
	Candidates []string
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%v: could not classify %q (candidates: %s); pass --type", ErrAmbiguous, e.Raw, strings.Join(e.Candidates, ", "))
}

func (e *AmbiguousError) Unwrap() error { return ErrAmbiguous }

// Detector resolves names with an injectable resolver and filesystem root.
type Detector struct {
	Resolver safety.Resolver
	// Stat lets tests stub the filesystem; defaults to os.Stat.
	Stat func(string) (os.FileInfo, error)
}

// Image reference grammar: [registry/]name[:tag][@sha256:hex]. Must have a
// "/", a ":tag" or "@" to be considered.
var imageRe = regexp.MustCompile(`^(?:(?P<host>[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?)/)?(?P<name>[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*)(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))?(?:@(?P<digest>sha256:[a-f0-9]{64}))?$`)

var hostnameRe = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$`)

// Detect classifies raw. override (from --type) skips detection but still
// normalises and validates.
func (d *Detector) Detect(ctx context.Context, raw string, override domain.TargetType) (domain.Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return domain.Target{}, errors.New("empty target")
	}
	if strings.HasPrefix(raw, "-") {
		return domain.Target{}, fmt.Errorf("target %q looks like a flag", raw)
	}
	if override != "" {
		return d.normalise(ctx, raw, override)
	}
	stat := d.Stat
	if stat == nil {
		stat = os.Stat
	}
	lower := strings.ToLower(raw)
	switch {
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return d.normalise(ctx, raw, domain.TargetURL)
	case strings.HasPrefix(lower, "aws://"), strings.HasPrefix(lower, "azure://"), strings.HasPrefix(lower, "gcp://"):
		return d.normalise(ctx, raw, domain.TargetCloud)
	}
	if _, err := stat(raw); err == nil {
		return d.normalise(ctx, raw, domain.TargetPath)
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return d.normalise(ctx, raw, domain.TargetHost)
	}
	if _, err := netip.ParsePrefix(raw); err == nil {
		return d.normalise(ctx, raw, domain.TargetCIDR)
	}
	var candidates []string
	if m := imageRe.FindStringSubmatch(raw); m != nil && (strings.Contains(raw, "/") || strings.Contains(raw, ":") || strings.Contains(raw, "@")) {
		host := m[imageRe.SubexpIndex("host")]
		// A leading segment with a dot or port is a registry; if it resolves
		// this is more likely a hostname than an image. Plain segments
		// ("library/nginx") are namespaces, not registries.
		isRegistry := host != "" && (strings.Contains(host, ".") || strings.Contains(host, ":"))
		if !isRegistry || !d.resolves(ctx, host) {
			return d.normalise(ctx, raw, domain.TargetImage)
		}
		candidates = append(candidates, "image")
	}
	if hostnameRe.MatchString(raw) {
		if d.resolves(ctx, raw) {
			return d.normalise(ctx, raw, domain.TargetHost)
		}
		candidates = append(candidates, "host (does not resolve)")
	}
	candidates = append(candidates, "path (does not exist)")
	return domain.Target{}, &AmbiguousError{Raw: raw, Candidates: candidates}
}

func (d *Detector) resolves(ctx context.Context, host string) bool {
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupIPAddr(ctx, strings.TrimSuffix(host, "."))
	return err == nil && len(addrs) > 0
}

func (d *Detector) normalise(ctx context.Context, raw string, typ domain.TargetType) (domain.Target, error) {
	t := domain.Target{Raw: raw, Type: typ}
	switch typ {
	case domain.TargetURL:
		u, err := url.Parse(raw)
		if err == nil && u.User != nil {
			return t, ErrURLCredentials
		}
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return t, fmt.Errorf("invalid URL %q", raw)
		}
		u.Fragment = ""
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		if u.Path == "" {
			u.Path = "/"
		}
		t.Value = u.String()
		t.Hostname = u.Hostname()
		t.Public = d.isPublic(ctx, t.Hostname)
	case domain.TargetHost:
		h := strings.ToLower(strings.TrimSuffix(raw, "."))
		if ip, err := netip.ParseAddr(h); err == nil {
			t.Value = ip.Unmap().String()
			t.Hostname = t.Value
			t.Public = !safety.IsPrivate(ip)
		} else {
			if !hostnameRe.MatchString(h) {
				return t, fmt.Errorf("invalid hostname %q", raw)
			}
			t.Value = h
			t.Hostname = h
			t.Public = d.isPublic(ctx, h)
		}
	case domain.TargetCIDR:
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return t, fmt.Errorf("invalid CIDR %q", raw)
		}
		p = p.Masked()
		t.Value = p.String()
		t.Public = !safety.IsPrivate(p.Addr())
	case domain.TargetPath:
		abs, err := filepath.Abs(raw)
		if err != nil {
			return t, err
		}
		abs, err = filepath.EvalSymlinks(abs)
		if err != nil {
			return t, fmt.Errorf("path %q: %w", raw, err)
		}
		t.Value = abs
		stat := d.Stat
		if stat == nil {
			stat = os.Stat
		}
		if _, err := stat(filepath.Join(abs, ".git")); err == nil {
			t.Labels = map[string]string{"repo": "git"}
		}
		// A `docker save` tarball (*.tar, *.tar.gz, *.tgz) is an image, not a
		// code tree: route it to the image engine and the image adapters. A
		// directory is never reclassified from its content: a repository that
		// happens to contain oci-layout and index.json stays a path (and gets
		// code, secret and IaC checks); an OCI layout needs --type image.
		if isLocalImageArchive(abs) {
			t.Type = domain.TargetImage
			t.Labels = map[string]string{ImageSourceLabel: ImageSourceDockerTar}
		}
	case domain.TargetImage:
		// --type image on something that exists on disk: a local archive file
		// or an OCI layout directory, which must carry a valid oci-layout
		// marker; anything else on disk is an error, not a registry reference.
		if abs, err := filepath.Abs(raw); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil {
				if st, err := os.Lstat(real); err == nil {
					src, err := localImageSource(real, st)
					if err != nil {
						return t, err
					}
					t.Value = real
					t.Labels = map[string]string{ImageSourceLabel: src}
					return t, nil
				}
			}
		}
		if imageRe.FindStringSubmatch(raw) == nil {
			return t, fmt.Errorf("invalid image reference %q", raw)
		}
		t.Value = raw
	case domain.TargetCloud:
		if !strings.HasPrefix(raw, "aws://") {
			return t, fmt.Errorf("only aws:// cloud targets are recognised (got %q)", raw)
		}
		t.Value = raw
	default:
		return t, fmt.Errorf("unknown target type %q", typ)
	}
	return t, nil
}

// Image source labels (mirrored by engine/image, which cannot be imported
// here without a cycle; the image package's tests pin the equality).
const (
	ImageSourceLabel     = "source"
	ImageSourceDockerTar = "docker-archive"
	ImageSourceOCILayout = "oci-layout"
)

// localImageSource classifies an existing path given with --type image: a
// regular file must look like a `docker save` archive and a directory must
// be a valid OCI layout.
func localImageSource(abs string, st os.FileInfo) (string, error) {
	if st.IsDir() {
		if err := ValidateOCILayout(abs); err != nil {
			return "", err
		}
		return ImageSourceOCILayout, nil
	}
	if !isLocalImageArchive(abs) {
		return "", fmt.Errorf("%s is not a container image archive (expected a `docker save` tar, optionally gzipped, named *.tar, *.tar.gz or *.tgz)", abs)
	}
	return ImageSourceDockerTar, nil
}

// ociLayoutVersionRe accepts the imageLayoutVersion values of the OCI image
// layout spec (1.0.0 today; any 1.x stays compatible).
var ociLayoutVersionRe = regexp.MustCompile(`^1\.[0-9]+\.[0-9]+$`)

// ValidateOCILayout checks that dir is an OCI image layout: a regular
// oci-layout file holding {"imageLayoutVersion":"1.x.y"} and a regular
// index.json. Symlinks are not followed. It is the only test that makes a
// directory an image target, and only with --type image.
func ValidateOCILayout(dir string) error {
	marker := filepath.Join(dir, "oci-layout")
	st, err := os.Lstat(marker)
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not an OCI layout (no oci-layout file)", dir)
	}
	if st.Size() > 4096 {
		return fmt.Errorf("%s: oci-layout file is too large to be a layout marker", dir)
	}
	b, err := os.ReadFile(marker)
	if err != nil {
		return err
	}
	var layout struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := json.Unmarshal(b, &layout); err != nil || !ociLayoutVersionRe.MatchString(layout.Version) {
		return fmt.Errorf("%s: oci-layout is not {\"imageLayoutVersion\":\"1.0.0\"}", dir)
	}
	if st, err := os.Lstat(filepath.Join(dir, "index.json")); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s: not an OCI layout (no index.json)", dir)
	}
	return nil
}

// isLocalImageArchive reports whether abs is a regular file named like a
// `docker save` archive (*.tar, *.tar.gz, *.tgz) whose first 64 KiB hold an
// image manifest, index or layer entry. Symlinks are not followed.
func isLocalImageArchive(abs string) bool {
	st, err := os.Lstat(abs)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	lower := strings.ToLower(abs)
	if !strings.HasSuffix(lower, ".tar") && !strings.HasSuffix(lower, ".tar.gz") && !strings.HasSuffix(lower, ".tgz") {
		return false
	}
	f, err := os.Open(abs)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	var r io.Reader = bytes.NewReader(head)
	if n >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return false
		}
		r = gz
	}
	tr := tar.NewReader(r)
	for i := 0; i < 64; i++ {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		base := filepath.Base(hdr.Name)
		if base == "manifest.json" || base == "index.json" || base == "oci-layout" || strings.HasSuffix(hdr.Name, "/layer.tar") || strings.HasPrefix(hdr.Name, "blobs/sha256/") {
			return true
		}
	}
	return false
}

// isPublic resolves all A/AAAA records; any non-private answer (or a
// resolution failure, which is the conservative choice) counts as public.
func (d *Detector) isPublic(ctx context.Context, host string) bool {
	ips, err := safety.ResolveAll(ctx, d.Resolver, host)
	if err != nil {
		return true
	}
	for _, ip := range ips {
		if !safety.IsPrivate(ip) {
			return true
		}
	}
	return false
}

// ParseType validates a --type value.
func ParseType(s string) (domain.TargetType, error) {
	switch domain.TargetType(strings.ToLower(s)) {
	case "":
		return "", nil
	case domain.TargetURL, domain.TargetHost, domain.TargetCIDR, domain.TargetPath, domain.TargetImage, domain.TargetCloud:
		return domain.TargetType(strings.ToLower(s)), nil
	}
	return "", fmt.Errorf("unknown --type %q (url|host|cidr|path|image|cloud)", s)
}

// Describe returns the wizard's "Looks like a ..." sentence.
func Describe(t domain.Target) string {
	switch t.Type {
	case domain.TargetURL:
		return "a website: " + t.Value
	case domain.TargetHost:
		return "a host: " + t.Value
	case domain.TargetCIDR:
		return "a network range: " + t.Value
	case domain.TargetPath:
		if t.Labels["repo"] != "" {
			return "a code repository: " + t.Value
		}
		return "a directory or file: " + t.Value
	case domain.TargetImage:
		return "a container image: " + t.Value
	case domain.TargetCloud:
		return "a cloud account: " + t.Value
	}
	return string(t.Type) + ": " + t.Value
}
