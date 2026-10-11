package adapter_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/adapter/grype"
	"github.com/gerald/scnr/internal/adapter/nmap"
	"github.com/gerald/scnr/internal/adapter/nuclei"
	"github.com/gerald/scnr/internal/adapter/prowler"
	"github.com/gerald/scnr/internal/adapter/semgrep"
	"github.com/gerald/scnr/internal/adapter/trivy"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/safety"
)

// TestNoForbiddenFlagLiteralsInAdapterSources inspects every non-test Go
// file under internal/adapter/* and asserts that no string literal that
// looks like a flag (leading '-') is a forbidden one (SAFETY.md item 10).
// Values such as the -et exclusion list do not start with '-' and are
// legitimately allowed to name the behaviours being switched off.
func TestNoForbiddenFlagLiteralsInAdapterSources(t *testing.T) {
	var files []string
	filepath.WalkDir("..", func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == "adaptertest" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") && strings.Contains(filepath.ToSlash(p), "/adapter/") {
			files = append(files, p)
		}
		return nil
	})
	if len(files) < 6 {
		t.Fatalf("expected adapter sources, found %v", files)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		node, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(node, func(n ast.Node) bool {
			if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == 1 && (vs.Names[0].Name == "Forbidden" || vs.Names[0].Name == "forbiddenValues") {
				return false // the deny lists themselves
			}
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			for _, part := range strings.Fields(s) {
				if strings.HasPrefix(part, "-") {
					if err := adapter.CheckForbidden([]string{part}); err != nil {
						t.Errorf("%s: forbidden flag literal %q", fset.Position(lit.Pos()), part)
					}
				}
			}
			// semgrep's "auto" config uploads project metadata: the literal
			// must not appear anywhere in an adapter source.
			if strings.EqualFold(s, "auto") || strings.HasSuffix(strings.ToLower(s), "=auto") {
				t.Errorf("%s: forbidden config value %q", fset.Position(lit.Pos()), s)
			}
			return true
		})
	}
}

func TestCheckForbidden(t *testing.T) {
	for _, bad := range [][]string{{"--script", "vuln"}, {"--script=vuln"}, {"-sU"}, {"-O"}, {"-dast"}, {"-fuzz"}, {"-bruteforce"}, {"--brute-force"},
		// Finding 7: nmap default scripts / aggressive, nuclei code+headless protocols and redirect following.
		{"-sC"}, {"-A"}, {"-code"}, {"-headless"}, {"-fr"}, {"-follow-redirects"}, {"-follow-redirects=true"},
		// Combined nmap scan types that smuggle U or C.
		{"-sTU"}, {"-sVC"}, {"-sSU"}, {"-sCV"},
		// Phase 3: semgrep autofix/pro/metrics/registry-auto, trivy client-server and tokens, grype hiding unfixed.
		{"--autofix"}, {"--pro"}, {"--metrics=on"}, {"--metrics=auto"}, {"--config", "auto"}, {"--config=auto"}, {"-c", "AUTO"}, {"--enable-version-check"},
		{"--server", "http://x"}, {"--token", "t"}, {"--token-header", "h"}, {"--custom-headers", "x"}, {"--only-fixed"}, {"--db-auto-update=true"},
		// Phase 4b: prowler fixers, Security Hub / S3 upload, Slack, Shodan, browser auth, user config file.
		{"--fixer"}, {"-S"}, {"--security-hub"}, {"--send-sh-only-fails"}, {"-B", "bucket"}, {"--output-bucket", "b"}, {"--output-bucket-no-assume", "b"}, {"--slack"}, {"--shodan", "k"}, {"--browser-auth"}, {"--config-file", "/x"}} {
		if err := adapter.CheckForbidden(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	for _, ok := range [][]string{{"-et", "dos,fuzz,intrusive,bruteforce,dast"}, {"-oX", "-"}, {"-sT", "-sV", "-Pn"}, {"-sTV"}, {"-o", "/tmp/x"}, {"--open"},
		{"-silent"}, {"-severity", "info"}, {"-sni", "app.example"}, {"-type", "http"}, {"-disable-redirects"}, {"-H", "Host: app.example"}, {"-duc"},
		{"--metrics=off"}, {"--config", "p/default"}, {"--config", "/opt/rules"}, {"--output", "/tmp/o.json"}, {"--scanners", "vuln,misconfig,secret"}, {"--skip-db-update"}, {"--disable-telemetry"}, {"-o", "json"}, {"--file", "/tmp/g.json"}, {"--oss-only"},
		{"aws", "-M", "json-ocsf", "-o", "/tmp/s", "-F", "prowler", "-z", "-b", "--no-color", "-p", "audit", "-f", "us-east-1"}} {
		if err := adapter.CheckForbidden(ok); err != nil {
			t.Errorf("%v refused: %v", ok, err)
		}
	}
}

// TestArgBuildersNeverEmitForbiddenFlags runs every adapter's Args over
// representative targets and options and checks the result.
func TestArgBuildersNeverEmitForbiddenFlags(t *testing.T) {
	nm, err := nmap.New()
	if err != nil {
		t.Fatal(err)
	}
	tv, err := trivy.New()
	if err != nil {
		t.Fatal(err)
	}
	gr, err := grype.New()
	if err != nil {
		t.Fatal(err)
	}
	pw, err := prowler.New([]string{"us-east-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := safety.NewScope(nil, nil)
	for _, public := range []bool{false, true} {
		limits, _, _ := safety.NewLimits(public, safety.LimitRequest{})
		for _, pname := range engine.ProfileNames() {
			p, _ := engine.ProfileByName(pname)
			for _, online := range []bool{false, true} {
				o := engine.Options{Profile: p, Limiter: limits, Scope: scope, Dialer: &safety.Dialer{Scope: scope, Limits: limits}, Scratch: t.TempDir(), Online: online, SemgrepRules: "/opt/rules"}
				if online {
					o.SemgrepRules = ""
				}
				for _, ad := range []adapter.Adapter{nm, nuclei.New(), semgrep.New(), tv, gr, pw} {
					for _, tg := range []domain.Target{
						{Type: domain.TargetHost, Value: "10.0.0.5", Hostname: "10.0.0.5"},
						{Type: domain.TargetURL, Value: "http://10.0.0.5:8080/", Hostname: "10.0.0.5"},
						{Type: domain.TargetCIDR, Value: "10.0.0.0/28"},
						{Type: domain.TargetPath, Value: "/repo/dir with space"},
						{Type: domain.TargetImage, Value: "/images/app.tar", Labels: map[string]string{image.SourceLabel: image.SourceDockerTar}},
						{Type: domain.TargetImage, Value: "/images/oci", Labels: map[string]string{image.SourceLabel: image.SourceOCILayout}},
						{Type: domain.TargetCloud, Value: "aws://123456789012", Labels: map[string]string{"profile": "audit"}},
					} {
						if !ad.Supports(tg) {
							continue
						}
						args, err := ad.Args(tg, o)
						if err != nil {
							t.Fatalf("%s %s: %v", ad.Name(), tg.Value, err)
						}
						if err := adapter.CheckForbidden(args); err != nil {
							t.Errorf("%s %s: %v (%v)", ad.Name(), tg.Value, err, args)
						}
						for _, a := range args {
							if strings.ContainsAny(a, ";|&$`\n") {
								t.Errorf("%s: shell metacharacter in argv %q", ad.Name(), a)
							}
						}
						// Image adapters never name a registry: only local archive sources.
						if tg.Type == domain.TargetImage {
							j := strings.Join(args, " ")
							if !strings.Contains(j, tg.Value) || strings.Contains(j, "docker.io") || strings.Contains(j, "registry:") {
								t.Errorf("%s: image argv must name the local archive only: %v", ad.Name(), args)
							}
						}
					}
				}
			}
		}
	}
	// Registry references are refused by every image-capable adapter (skip,
	// never a pull through the tool's own network stack).
	for _, ad := range []adapter.Adapter{tv, gr} {
		var skip *engine.SkipError
		if _, err := ad.Args(domain.Target{Type: domain.TargetImage, Value: "docker.io/library/alpine:3.18"}, engine.Options{Scratch: t.TempDir(), Online: true}); !errors.As(err, &skip) {
			t.Errorf("%s pulled a registry reference: %v", ad.Name(), err)
		}
	}
	// Phase 3 specifics: semgrep metrics off and never auto; trivy telemetry
	// off and no DB download when offline; grype DB auto-update off when offline.
	sg, _ := semgrep.New().Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, engine.Options{Scratch: t.TempDir(), Online: true})
	if j := " " + strings.Join(sg, " ") + " "; !strings.Contains(j, " --metrics=off ") || strings.Contains(j, " auto ") || !strings.Contains(j, " --oss-only ") {
		t.Fatalf("semgrep args: %v", sg)
	}
	// Offline without local rules: skipped, so p/default is never fetched.
	var sgSkip *engine.SkipError
	if _, err := semgrep.New().Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, engine.Options{Scratch: t.TempDir()}); !errors.As(err, &sgSkip) {
		t.Fatalf("semgrep offline without rules must skip: %v", err)
	}
	tvArgs, _ := tv.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, engine.Options{Scratch: t.TempDir(), Online: false})
	if j := " " + strings.Join(tvArgs, " ") + " "; !strings.Contains(j, " --disable-telemetry ") || !strings.Contains(j, " --skip-db-update ") || !strings.Contains(j, " --skip-check-update ") {
		t.Fatalf("trivy offline args: %v", tvArgs)
	}
	gr.Args(domain.Target{Type: domain.TargetPath, Value: "/repo"}, engine.Options{Scratch: t.TempDir(), Online: false})
	if env := strings.Join(gr.Env(), " "); !strings.Contains(env, "GRYPE_DB_AUTO_UPDATE=false") || !strings.Contains(env, "GRYPE_CHECK_FOR_APP_UPDATE=false") {
		t.Fatalf("grype offline env: %v", gr.Env())
	}
	// Nuclei specifics: interactsh off, exclusion list present, HTTP templates
	// only, redirects not followed (nuclei bypasses the safety dialer).
	args, _ := nuclei.New().Args(domain.Target{Type: domain.TargetURL, Value: "http://10.0.0.5/"}, engine.Options{Scratch: t.TempDir()})
	joined := " " + strings.Join(args, " ") + " "
	for _, want := range []string{" -ni ", " -et dos,fuzz,intrusive,bruteforce,dast ", " -type http ", " -disable-redirects ", " -duc "} {
		if !strings.Contains(joined, want) {
			t.Fatalf("nuclei args missing %q: %v", want, args)
		}
	}
	// Exec refuses a forbidden argv even if an arg builder regressed.
	b := &adapter.Base{BinaryName: "go", VersionArgs: []string{"version"}}
	if _, err := b.Detect(context.Background()); err != nil {
		t.Skip("go toolchain not found on PATH")
	}
	if _, err := b.Exec(context.Background(), t.TempDir(), []string{"--script", "x"}, 0); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("Exec accepted forbidden flag: %v", err)
	}
}
