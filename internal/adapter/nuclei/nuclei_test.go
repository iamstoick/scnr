package nuclei

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

func opts(t *testing.T) engine.Options {
	t.Helper()
	limits, _, _ := safety.NewLimits(false, safety.LimitRequest{})
	p, _ := engine.ProfileByName("standard")
	return engine.Options{Profile: p, Limiter: limits, Scratch: t.TempDir(), Redactor: safety.NewRedactor()}
}

func parseFixture(t *testing.T, version string) (map[string]domain.Finding, error) {
	t.Helper()
	f, err := os.Open(filepath.Join(adaptertest.FixtureDir(t, "nuclei", version), "results.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]domain.Finding{}
	err = New().Parse(f, func(fd domain.Finding) error { out[fd.RuleID] = fd; return nil })
	return out, err
}

// Acceptance 2.2: two nuclei versions parse to expected findings.
func TestParseFixtures(t *testing.T) {
	got, err := parseFixture(t, "3.1.0")
	if err != nil || len(got) != 3 {
		t.Fatalf("3.1.0: %d findings, err %v", len(got), err)
	}
	cve := got["nuclei:CVE-2021-41773"]
	if cve.Severity != domain.High || cve.CWE != "CWE-22" || len(cve.CVEs) != 1 || cve.CVEs[0] != "CVE-2021-41773" || cve.CVSS == nil || cve.CVSS.Score != 7.5 ||
		cve.AssetKey != "url:http://127.0.0.1:8080/" || !strings.Contains(cve.WhatItIs, "description from nuclei") || len(cve.References) != 2 {
		t.Fatalf("cve finding %+v", cve)
	}
	git := got["nuclei:git-config"]
	if git.Severity != domain.Medium || git.CWE != "CWE-200" || !strings.HasSuffix(git.Location, "/.git/config") || len(git.Evidence) != 2 {
		t.Fatalf("git finding %+v", git)
	}
	for _, f := range got {
		for _, ev := range f.Evidence {
			if strings.Contains(ev.Redacted, "curl") {
				t.Fatalf("curl-command leaked into evidence: %q", ev.Redacted)
			}
		}
		if f.Fingerprint == "" || f.HowToFix == "" || f.Engine != Name {
			t.Fatalf("incomplete %+v", f)
		}
	}

	// 3.3.4 has two hostile lines: parse keeps the good ones and reports the bad count.
	got, err = parseFixture(t, "3.3.4")
	if err == nil || !strings.Contains(err.Error(), "2 line(s)") {
		t.Fatalf("hostile lines must be reported: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("3.3.4: %d findings", len(got))
	}
	if _, ok := got["nuclei:../../etc/passwd"]; ok {
		t.Fatal("hostile template id accepted")
	}
	struts := got["nuclei:CVE-2017-5638"]
	if struts.Severity != domain.Critical || struts.CVSS == nil || struts.CVSS.Score != 10 || struts.CWE != "CWE-20" {
		t.Fatalf("struts %+v", struts)
	}
	// The response carried a bearer JWT: redacted before it became evidence.
	for _, ev := range struts.Evidence {
		if strings.Contains(ev.Redacted, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0") {
			t.Fatalf("token leaked: %q", ev.Redacted)
		}
	}
	// Control characters from the DS_Store body are stripped.
	for _, ev := range got["nuclei:ds-store-file"].Evidence {
		if strings.ContainsRune(ev.Redacted, 0) || strings.ContainsRune(ev.Redacted, 1) {
			t.Fatal("control chars in evidence")
		}
	}
}

// Finding 5: an over-long JSONL line is dropped and counted; the lines
// before and after it are still emitted (bufio.Scanner used to abort).
func TestParseKeepsLinesAfterOverLongLine(t *testing.T) {
	line := func(id, path, extra string) string {
		return `{"template-id":"` + id + `","info":{"name":"n","severity":"high"},"host":"http://10.0.0.5","matched-at":"http://10.0.0.5` + path + `"` + extra + `}`
	}
	in := line("first-ok", "/a", "") + "\n" +
		line("big-response", "/b", `,"response":"`+strings.Repeat("A", maxLineSize)+`"`) + "\n" +
		line("later-finding", "/c", "") + "\n" +
		line("unterminated", "/d", "") // no trailing newline
	var got []string
	err := New().Parse(strings.NewReader(in), func(f domain.Finding) error { got = append(got, f.RuleID); return nil })
	if err == nil || !strings.Contains(err.Error(), "1 line(s)") {
		t.Fatalf("over-long line must be reported once: %v", err)
	}
	if strings.Join(got, ",") != "nuclei:first-ok,nuclei:later-finding,nuclei:unterminated" {
		t.Fatalf("emitted %v", got)
	}
	// Two over-long lines in a row, then a good one.
	in = line("x", "/b", `,"response":"`+strings.Repeat("B", maxLineSize)+`"`) + "\n" +
		line("y", "/b", `,"response":"`+strings.Repeat("C", 3*maxLineSize)+`"`) + "\n" + line("ok", "/c", "") + "\n"
	got = nil
	err = New().Parse(strings.NewReader(in), func(f domain.Finding) error { got = append(got, f.RuleID); return nil })
	if err == nil || !strings.Contains(err.Error(), "2 line(s)") || len(got) != 1 || got[0] != "nuclei:ok" {
		t.Fatalf("got %v err %v", got, err)
	}
}

// Acceptance 2.7 (unit level): args use -ni and the exclusion tags, never
// forbidden flags; the full fake-binary run is in TestRunWithFakeBinary.
func TestArgs(t *testing.T) {
	a := New()
	o := opts(t)
	args, err := a.Args(domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1:8080/", Hostname: "127.0.0.1"}, o)
	if err != nil {
		t.Fatal(err)
	}
	assertSafeArgs(t, args, o.Scratch)
	if strings.Contains(strings.Join(args, " "), "Host:") {
		t.Fatalf("IP-literal target must not get a Host header: %v", args)
	}
	if _, err := a.Args(domain.Target{Type: domain.TargetURL, Value: "http://u:p@127.0.0.1/"}, o); err == nil {
		t.Fatal("userinfo accepted")
	}
	if _, err := a.Args(domain.Target{Type: domain.TargetHost, Value: "-dast"}, o); err == nil {
		t.Fatal("flag-shaped target accepted")
	}
	o.NucleiTemplatesDir = "/opt/nuclei-templates"
	args, _ = a.Args(domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}, o)
	if j := " " + strings.Join(args, " ") + " "; !strings.Contains(j, " -t /opt/nuclei-templates ") {
		t.Fatalf("templates dir not passed: %v", args)
	}
}

func pinnedOpts(t *testing.T, public bool, host string, addrs ...string) engine.Options {
	t.Helper()
	o := opts(t)
	scope, _ := safety.NewScope([]string{host}, nil, nil)
	o.Limiter, _, _ = safety.NewLimits(public, safety.LimitRequest{})
	o.Dialer = &safety.Dialer{Scope: scope, Limits: o.Limiter}
	var ips []netip.Addr
	for _, a := range addrs {
		ips = append(ips, netip.MustParseAddr(a))
	}
	if len(ips) > 0 {
		o.Dialer.Pin(host, ips)
	}
	return o
}

// Finding 1: nuclei does its own DNS, so a hostname target is rewritten to
// the single gate-pinned address with Host header and SNI carrying the
// name. A public hostname that cannot be pinned that way is skipped, never
// scanned through a fresh DNS answer; private-only scans may run unpinned.
func TestArgsPinHostnameToAuthorisedAddress(t *testing.T) {
	a := New()
	cases := []struct {
		name   string
		target domain.Target
		opts   engine.Options
		wantU  string
	}{
		{"url single pin", domain.Target{Type: domain.TargetURL, Value: "https://app.example:8443/x", Hostname: "app.example", Public: true}, pinnedOpts(t, true, "app.example", "203.0.113.5"), "https://203.0.113.5:8443/x"},
		{"url default port", domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, pinnedOpts(t, true, "app.example", "203.0.113.5"), "https://203.0.113.5/"},
		{"url ipv6 pin", domain.Target{Type: domain.TargetURL, Value: "http://app.example/", Hostname: "app.example", Public: true}, pinnedOpts(t, true, "app.example", "2001:db8::5"), "http://[2001:db8::5]/"},
		{"host single pin", domain.Target{Type: domain.TargetHost, Value: "app.example", Hostname: "app.example", Public: true}, pinnedOpts(t, true, "app.example", "203.0.113.5"), "203.0.113.5"},
		{"private single pin", domain.Target{Type: domain.TargetURL, Value: "http://intranet.test/", Hostname: "intranet.test"}, pinnedOpts(t, false, "intranet.test", "10.1.2.3"), "http://10.1.2.3/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args, err := a.Args(c.target, c.opts)
			if err != nil {
				t.Fatal(err)
			}
			j := " " + strings.Join(args, " ") + " "
			for _, want := range []string{" -u " + c.wantU + " ", " -H Host: " + c.target.Hostname + " ", " -sni " + c.target.Hostname + " ", " -disable-redirects ", " -type http ", " -response-size-save 65536 "} {
				if !strings.Contains(j, want) {
					t.Errorf("missing %q in %v", want, args)
				}
			}
			if strings.Contains(j, c.target.Hostname+"/") || strings.Contains(j, "-u "+c.target.Hostname) {
				t.Errorf("hostname still used as the target: %v", args)
			}
			if err := adapter.CheckForbidden(args); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Public target, two pinned addresses: skipped with a reason and a hint.
	var skip *engine.SkipError
	_, err := a.Args(domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, pinnedOpts(t, true, "app.example", "203.0.113.5", "203.0.113.6"))
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "2 gate-pinned addresses") || !strings.Contains(skip.Reason, "--skip-engines "+Name) || !strings.Contains(skip.Reason, "scnr doctor") {
		t.Fatalf("multi-address public target must be skipped with a hint: %v", err)
	}
	// Public target, nothing pinned (no dialer at all): skipped too.
	_, err = a.Args(domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, opts(t))
	if !errors.As(err, &skip) || !strings.Contains(skip.Reason, "no gate-pinned address") {
		t.Fatalf("unpinned public target must be skipped: %v", err)
	}
	// A private target in a scan that also pinned a public one is not run unpinned either.
	o := pinnedOpts(t, true, "app.example", "203.0.113.5")
	_, err = a.Args(domain.Target{Type: domain.TargetURL, Value: "http://intranet.test/", Hostname: "intranet.test"}, o)
	if !errors.As(err, &skip) {
		t.Fatalf("unpinned private name during a public scan must be skipped: %v", err)
	}
	// Private-only scan, several addresses: runs unpinned by name.
	args, err := a.Args(domain.Target{Type: domain.TargetURL, Value: "http://intranet.test/", Hostname: "intranet.test"}, pinnedOpts(t, false, "intranet.test", "10.1.2.3", "10.1.2.4"))
	if err != nil || !strings.Contains(" "+strings.Join(args, " ")+" ", " -u http://intranet.test/ ") || strings.Contains(strings.Join(args, " "), "Host:") {
		t.Fatalf("private-only scan should run unpinned: %v %v", args, err)
	}
	// The plan reports the skip instead of failing.
	adaptertest.Install(t, "nuclei", "-version", "v3.1.0", "")
	p, err := a.Plan(context.Background(), domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, opts(t))
	if err != nil || !strings.Contains(p.Summary, "will be skipped") || p.Network {
		t.Fatalf("plan %+v %v", p, err)
	}
}

// Finding 1 (end to end with a fake binary): the recorded argv names the
// pinned address, not the hostname.
func TestRunWithFakeBinaryUsesPinnedAddress(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "nuclei", "3.1.0"), "results.jsonl")
	argvPath := adaptertest.Install(t, "nuclei", "-version", "[INF] Nuclei Engine Version: v3.1.0", adaptertest.CopyToOutBody(fixture))
	o := pinnedOpts(t, true, "app.example", "203.0.113.5")
	n := 0
	err := New().Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, o, func(domain.Finding) error { n++; return nil })
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	argv := adaptertest.Argv(t, argvPath)
	j := " " + strings.Join(argv, " ") + " "
	for _, want := range []string{" -u https://203.0.113.5/ ", " -H Host: app.example ", " -sni app.example ", " -disable-redirects ", " -type http "} {
		if !strings.Contains(j, want) {
			t.Errorf("argv missing %q: %v", want, argv)
		}
	}
	if strings.Contains(j, " -u https://app.example") {
		t.Fatalf("hostname passed to nuclei: %v", argv)
	}
	// Two pinned addresses: the binary is never invoked; the engine skips.
	argvPath = adaptertest.Install(t, "nuclei", "-version", "v3.1.0", adaptertest.CopyToOutBody(fixture))
	o = pinnedOpts(t, true, "app.example", "203.0.113.5", "203.0.113.6")
	err = New().Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "https://app.example/", Hostname: "app.example", Public: true}, o, nil)
	var skip *engine.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("want skip, got %v", err)
	}
	if _, err := os.Stat(argvPath); err == nil {
		t.Fatal("nuclei was invoked for an unpinnable public target")
	}
}

func assertSafeArgs(t *testing.T, args []string, scratch string) {
	t.Helper()
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" -ni ", " -et " + ExcludedTags + " ", " -jsonl ", " -silent ", " -duc ", " -type http ", " -disable-redirects ", " -response-size-save 65536 ", " -rl 20 ", " -c 64 ", " -o " + filepath.Join(scratch, outputFile) + " "} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %s", want, joined)
		}
	}
	if err := adapter.CheckForbidden(args); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"-dast", "-fuzz", "-headless", "-code", "-fr", "-follow-redirects", "-interactsh-server", "-iserver"} {
		for _, a := range args {
			if a == bad {
				t.Fatalf("forbidden %q in %v", bad, args)
			}
		}
	}
}

func TestRunWithFakeBinary(t *testing.T) {
	fixture := filepath.Join(adaptertest.FixtureDir(t, "nuclei", "3.1.0"), "results.jsonl")
	argvPath := adaptertest.Install(t, "nuclei", "-version", "[INF] Nuclei Engine Version: v3.1.0", adaptertest.CopyToOutBody(fixture))
	a := New()
	o := opts(t)
	n := 0
	err := a.Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1:8080/", Hostname: "127.0.0.1"}, o, func(domain.Finding) error { n++; return nil })
	if err != nil || n != 3 || a.Version() != "3.1.0" {
		t.Fatalf("n=%d version=%q err=%v", n, a.Version(), err)
	}
	assertSafeArgs(t, adaptertest.Argv(t, argvPath), o.Scratch)

	// Non-zero exit but output present: findings still parsed.
	adaptertest.Install(t, "nuclei", "-version", "v3.3.4", adaptertest.CopyToOutBody(fixture)+"; exit 1")
	n = 0
	if err := New().Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1:8080/"}, o, func(domain.Finding) error { n++; return nil }); err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// Non-zero exit and no output: a real failure with stderr tail.
	adaptertest.Install(t, "nuclei", "-version", "v3.3.4", `echo "FTL Could not run nuclei: no templates" >&2; exit 1`)
	if err := New().Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1:8080/"}, o, nil); err == nil || !strings.Contains(err.Error(), "no templates") {
		t.Fatalf("err %v", err)
	}
	// Missing -> skipped.
	adaptertest.Hide(t)
	err = New().Run(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://127.0.0.1:8080/"}, o, nil)
	var skip *engine.SkipError
	if !errors.As(err, &skip) {
		t.Fatalf("missing nuclei should skip: %v", err)
	}
}

// TestNucleiArgsIgnoreAllowIntrusive (D7): --allow-intrusive changes
// nothing in the nuclei adapter: excluded tags stay excluded and argv is
// byte-identical with and without the option.
func TestNucleiArgsIgnoreAllowIntrusive(t *testing.T) {
	a := New()
	tgt := domain.Target{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"}
	plain := opts(t)
	intrusive := plain
	intrusive.Scratch = plain.Scratch
	intrusive.Intrusive = true
	want, err := a.Args(tgt, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.Args(tgt, intrusive)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(want, "\x00") != strings.Join(got, "\x00") {
		t.Fatalf("argv differs:\n%q\n%q", want, got)
	}
	joined := " " + strings.Join(got, " ") + " "
	if !strings.Contains(joined, " -et "+ExcludedTags+" ") {
		t.Fatalf("excluded tags changed: %v", got)
	}
	for _, bad := range []string{" -dast ", " -intrusive "} {
		if strings.Contains(joined, bad) {
			t.Fatalf("intrusive flag enabled: %v", got)
		}
	}
}
