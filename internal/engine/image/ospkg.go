package image

import (
	"strings"

	"github.com/iamstoick/scnr/internal/engine/sca"
)

// Paths inside an image root (no leading slash) that the engine collects.
const (
	apkDB        = "lib/apk/db/installed"
	dpkgStatus   = "var/lib/dpkg/status"
	dpkgStatusD  = "var/lib/dpkg/status.d/"
	osRelease    = "etc/os-release"
	usrOSRelease = "usr/lib/os-release"
)

// rpmDBPaths signal an rpm-based image, which the native engine hands off
// to trivy/grype (Section 5.6).
var rpmDBPaths = []string{"var/lib/rpm/Packages", "var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/Packages.db"}

// OS identifies the image's distribution from os-release.
type OS struct {
	ID        string // alpine | debian | ubuntu | ...
	VersionID string // 3.18.4 | 12 | 22.04
	Name      string // PRETTY_NAME
	LTS       bool
}

// Ecosystem returns the OSV ecosystem for the distribution, or "" when OSV
// has no feed for it.
func (o OS) Ecosystem() string {
	switch o.ID {
	case "alpine":
		parts := strings.SplitN(o.VersionID, ".", 3)
		if len(parts) < 2 {
			return ""
		}
		return "Alpine:v" + parts[0] + "." + parts[1]
	case "debian":
		if major, _, _ := strings.Cut(o.VersionID, "."); major != "" {
			return "Debian:" + major
		}
	case "ubuntu":
		if o.VersionID != "" {
			if o.LTS {
				return "Ubuntu:" + o.VersionID + ":LTS"
			}
			return "Ubuntu:" + o.VersionID
		}
	}
	return ""
}

// parseOSRelease reads KEY=value lines (values optionally quoted).
func parseOSRelease(content []byte) OS {
	var o OS
	for _, l := range strings.Split(string(content), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			o.ID = strings.ToLower(v)
		case "VERSION_ID":
			o.VersionID = v
		case "PRETTY_NAME":
			o.Name = v
		case "VERSION":
			o.LTS = o.LTS || strings.Contains(v, "LTS")
		}
	}
	return o
}

// parseAPK reads /lib/apk/db/installed: records separated by blank lines
// with single-letter keys (P name, V version, o origin).
func parseAPK(content []byte, ecosystem, file string) []sca.Package {
	var d sca.Dedupe
	var name, version, origin string
	flush := func() {
		p := sca.Package{Ecosystem: ecosystem, Name: name, Version: version, Direct: true, File: file}
		if origin != "" && origin != name {
			p.Source = origin
		}
		d.Add(p)
		name, version, origin = "", "", ""
	}
	for _, l := range strings.Split(string(content), "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			flush()
			continue
		}
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		switch l[0] {
		case 'P':
			name = l[2:]
		case 'V':
			version = l[2:]
		case 'o':
			origin = l[2:]
		}
	}
	flush()
	return d.Packages()
}

// parseDpkg reads a dpkg status file (or a status.d entry): RFC822-style
// paragraphs; only installed packages count.
func parseDpkg(content []byte, ecosystem, file string) []sca.Package {
	var d sca.Dedupe
	var name, version, source, status string
	flush := func() {
		if status == "" || strings.Contains(status, "installed") {
			p := sca.Package{Ecosystem: ecosystem, Name: name, Version: version, Direct: true, File: file}
			if source != "" && source != name {
				p.Source = source
			}
			d.Add(p)
		}
		name, version, source, status = "", "", "", ""
	}
	for _, l := range strings.Split(string(content), "\n") {
		l = strings.TrimRight(l, "\r")
		if l == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.HasPrefix(l, " ") {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			name = v
		case "Version":
			version = v
		case "Status":
			status = v
		case "Source":
			// "Source: glibc (2.36-9)" names the source version too.
			source, _, _ = strings.Cut(v, " ")
		}
	}
	flush()
	return d.Packages()
}
