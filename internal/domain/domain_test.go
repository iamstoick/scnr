package domain

import "testing"

func TestFingerprintNormalisation(t *testing.T) {
	cases := []struct {
		name     string
		rule     string
		locA     string
		locB     string
		wantSame bool
	}{
		{"secret moved within file keeps hash-based fingerprint", "secret.aws-access-key", "src/a.py:10#abcd", "src/a.py:42#abcd", true},
		{"secret different hash differs", "secret.aws-access-key", "src/a.py:10#abcd", "src/a.py:10#ef01", false},
		{"url query stripped", "web.x", "https://Example.com/a?x=1", "https://example.com/a?x=2", true},
		{"host:port lowercased host", "net.open-port", "Host.Example:443", "host.example:443", true},
		{"different ports differ", "net.open-port", "h:443", "h:80", false},
		// Phase 3: the PURL in the rule ID identifies the package; lockfile
		// line numbers and tool-specific path prefixes never split a finding
		// between native SCA, trivy and grype.
		{"sca lockfile line ignored", "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20", "go.mod:5", "go.mod", true},
		{"sca leading slash ignored", "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20", "/package-lock.json", "./package-lock.json", true},
		{"sca different files differ", "sca.osv.CVE-2020-8203@pkg:npm/lodash@4.17.20", "a/package-lock.json", "b/package-lock.json", false},
		// IaC secret rules fingerprint like secrets: by evidence hash, not line.
		{"iac secret moved keeps fingerprint", "iac.docker.secret-in-env", "Dockerfile:3#abcd", "Dockerfile:5#abcd", true},
		{"iac secret different hash differs", "iac.tf.secret-in-variable-default", "main.tf:7#abcd", "main.tf:7#ef01", false},
		{"iac structural rule keeps line", "iac.tf.s3-public-acl", "main.tf:7", "main.tf:9", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := Fingerprint(c.rule, "host:x", c.locA)
			b := Fingerprint(c.rule, "host:x", c.locB)
			if (a == b) != c.wantSame {
				t.Fatalf("same=%v want %v (%s vs %s)", a == b, c.wantSame, a, b)
			}
		})
	}
	if Fingerprint("r", "a", "l") == Fingerprint("r", "b", "l") {
		t.Fatal("asset key must affect fingerprint")
	}
}

func TestSeverityParse(t *testing.T) {
	for i, n := range []string{"info", "low", "medium", "high", "critical"} {
		s, ok := ParseSeverity(n)
		if !ok || int(s) != i || s.String() != n {
			t.Fatalf("%s -> %v %v", n, s, ok)
		}
	}
	if _, ok := ParseSeverity("urgent"); ok {
		t.Fatal("unknown severity accepted")
	}
}

func TestTargetSetHashOrderIndependent(t *testing.T) {
	a := Target{Type: TargetHost, Value: "10.0.0.1"}
	b := Target{Type: TargetPath, Value: "/x"}
	if TargetSetHash([]Target{a, b}) != TargetSetHash([]Target{b, a}) {
		t.Fatal("hash depends on order")
	}
}
