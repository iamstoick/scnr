package nmap

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/adapter"
	"github.com/iamstoick/scnr/internal/adapter/adaptertest"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

func opts(t *testing.T, public bool) engine.Options {
	t.Helper()
	scope, _ := safety.NewScope(nil, []string{"10.0.0.1", "10.9.0.0/16"}, nil)
	limits, _, _ := safety.NewLimits(public, safety.LimitRequest{})
	p, _ := engine.ProfileByName("standard")
	d := &safety.Dialer{Scope: scope, Limits: limits}
	return engine.Options{Profile: p, Limiter: limits, Scope: scope, Dialer: d, Scratch: t.TempDir(), Redactor: safety.NewRedactor()}
}

func parseFixture(t *testing.T, version string) map[string][]domain.Finding {
	t.Helper()
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(adaptertest.FixtureDir(t, "nmap", version), "scan.xml"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]domain.Finding{}
	if err := a.Parse(f, func(fd domain.Finding) error { out[fd.RuleID] = append(out[fd.RuleID], fd); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// Acceptance 2.2: fixtures for two nmap versions parse to expected findings.
func TestParseFixtures(t *testing.T) {
	got := parseFixture(t, "7.80")
	if len(got["net.open-port"]) != 3 || len(got["net.exposed-db-port"]) != 1 {
		t.Fatalf("7.80: %v", summarise(got))
	}
	var mysql domain.Finding
	for _, f := range got["net.open-port"] {
		if strings.HasSuffix(f.Location, ":3306") {
			mysql = f
		}
	}
	if !strings.Contains(mysql.Title, "MySQL 5.7.29") || mysql.AssetKey != "host:10.0.0.5" || mysql.Evidence[0].Kind != "tool_output" {
		t.Fatalf("mysql finding %+v", mysql)
	}
	// Fingerprint matches what the native scanner would produce for the same port.
	if mysql.Fingerprint != domain.Fingerprint("net.open-port", "host:10.0.0.5", "10.0.0.5:3306") {
		t.Fatal("fingerprint differs from native scheme")
	}

	got = parseFixture(t, "7.94")
	// 22, 443, 6379 open; 3389 closed and 8080 filtered are ignored; 10.0.0.6 is down.
	if len(got["net.open-port"]) != 3 || len(got["net.exposed-db-port"]) != 1 || len(got["net.exposed-admin-port"]) != 0 {
		t.Fatalf("7.94: %v", summarise(got))
	}
	for _, f := range got["net.open-port"] {
		if f.AssetKey != "host:10.0.0.5" {
			t.Fatalf("down host leaked: %+v", f)
		}
	}
}

func TestParseRejectsMalformedAndEntities(t *testing.T) {
	a, _ := New()
	for name, in := range map[string]string{
		"truncated": `<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>`,
		"entity":    `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="&e;" addrtype="ipv4"/></host></nmaprun>`,
		"not xml":   `{"json":true}`,
	} {
		n := 0
		err := a.Parse(strings.NewReader(in), func(domain.Finding) error { n++; return nil })
		if err == nil && n > 0 {
			t.Errorf("%s: produced %d findings without error", name, n)
		}
	}
	// Hostile addr values never become asset keys.
	n := 0
	a.Parse(strings.NewReader(`<nmaprun><host><status state="up"/><address addr="evil\x00;rm -rf" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>`), func(domain.Finding) error { n++; return nil })
	if n != 0 {
		t.Fatal("non-IP address accepted")
	}
}

func TestArgs(t *testing.T) {
	a, _ := New()
	o := opts(t, false)
	o.Dialer.Pin("app.test", []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.7")})
	args, err := a.Args(domain.Target{Type: domain.TargetURL, Value: "https://app.test/", Hostname: "app.test"}, o)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-sT", "-sV", "-Pn", "-n", "-oX -", "--max-rate 500", "--max-parallelism 64", "--top-ports 1000", "--exclude", "10.0.0.1", "10.9.0.0/16", "169.254.169.254"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %s", want, joined)
		}
	}
	// The hostname itself is never passed: nmap scans the pinned addresses.
	if strings.Contains(joined, "app.test") || args[len(args)-2] != "10.0.0.5" || args[len(args)-1] != "10.0.0.7" {
		t.Fatalf("targets: %s", joined)
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	// Unpinned hostname is refused (no DNS by nmap).
	if _, err := a.Args(domain.Target{Type: domain.TargetHost, Value: "other.test", Hostname: "other.test"}, o); err == nil {
		t.Fatal("unpinned hostname accepted")
	}
	// Explicit ports and deep profile.
	o.Ports = []int{22, 80}
	args, _ = a.Args(domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, o)
	if !strings.Contains(strings.Join(args, " "), "-p 22,80") {
		t.Fatalf("ports: %v", args)
	}
	o.Ports = nil
	o.Profile.Name = "deep"
	args, _ = a.Args(domain.Target{Type: domain.TargetCIDR, Value: "10.0.0.0/24"}, o)
	if !strings.Contains(strings.Join(args, " "), "-p-") || args[len(args)-1] != "10.0.0.0/24" {
		t.Fatalf("deep: %v", args)
	}
	// A flag-shaped value can never reach argv.
	if _, err := a.Args(domain.Target{Type: domain.TargetCIDR, Value: "--script=vuln"}, o); err == nil {
		t.Fatal("flag-shaped CIDR accepted")
	}
}

func TestRunWithFakeBinaryAndSkipWhenMissing(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "nmap", "7.94"), "scan.xml")
	argvPath := adaptertest.Install(t, "nmap", "--version", "Nmap version 7.94 ( https://nmap.org )", adaptertest.CatBody(fixture))
	a, _ := New()
	o := opts(t, false)
	n := 0
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, o, func(f domain.Finding) error {
		n++
		if f.RuleID == "net.exposed-db-port" && f.Severity != domain.Medium {
			t.Errorf("private target exposure not downgraded: %+v", f)
		}
		return nil
	})
	if err != nil || n != 4 {
		t.Fatalf("run: n=%d err=%v", n, err)
	}
	if a.Version() != "7.94" {
		t.Fatalf("version %q", a.Version())
	}
	argv := adaptertest.Argv(t, argvPath)
	if err := adapter.CheckForbidden(argv); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"--script", "-sU", "-O", "-A"} {
		for _, a := range argv {
			if a == bad {
				t.Fatalf("forbidden %q in argv %v", bad, argv)
			}
		}
	}
	// Too-old version -> skipped.
	adaptertest.Install(t, "nmap", "--version", "Nmap version 7.60 ( https://nmap.org )", adaptertest.CatBody(fixture))
	old, _ := New()
	err = old.Run(context.Background(), domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, o, nil)
	var skip *engine.SkipError
	if !errors.As(err, &skip) || !strings.Contains(err.Error(), "older") {
		t.Fatalf("old version should skip: %v", err)
	}
	// Missing binary -> skipped with a doctor hint, never a failure.
	adaptertest.Hide(t)
	missing, _ := New()
	err = missing.Run(context.Background(), domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, o, nil)
	if !errors.As(err, &skip) || !strings.Contains(err.Error(), "scnr doctor") {
		t.Fatalf("missing binary should skip: %v", err)
	}
	p, err := missing.Plan(context.Background(), domain.Target{Type: domain.TargetHost, Value: "10.0.0.5"}, o)
	if err != nil || !strings.Contains(p.Summary, "skipped") {
		t.Fatalf("plan %+v %v", p, err)
	}
}

func TestRunReportsToolFailure(t *testing.T) {
	adaptertest.Install(t, "nmap", "--version", "Nmap version 7.94", "echo 'nmap: boom' >&2; exit 1")
	a, _ := New()
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, opts(t, false), nil)
	if err == nil || !strings.Contains(err.Error(), "exited 1") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err %v", err)
	}
}

func summarise(m map[string][]domain.Finding) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		out[k] = len(v)
	}
	return out
}
