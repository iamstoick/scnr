// Package codecheck is the pattern-grade SAST engine: regexes scoped to file
// types, each with authored what/why/fix prose. Every finding is Tentative
// and says so; dataflow-aware analysis is the semgrep adapter's job.
package codecheck

import (
	"context"
	"embed"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "codecheck"

// VerifyText is appended to every finding (acceptance 3.6).
const VerifyText = "Pattern match, verify in context: this is a text pattern, not a dataflow analysis."

const (
	maxLineBytes      = 2048
	maxMatchesPerFile = 200
)

// File type groups for scoping.
var (
	extPy     = []string{".py"}
	extJS     = []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}
	extGo     = []string{".go"}
	extRb     = []string{".rb"}
	extPHP    = []string{".php"}
	extJVM    = []string{".java", ".kt", ".scala"}
	extConfig = []string{".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".py", ".php"}
	extShell  = []string{".sh", ".bash", ".zsh", "Makefile", ".yml", ".yaml", ".mk"}
	extHTML   = []string{".html", ".htm", ".jsx", ".tsx", ".vue", ".ejs", ".hbs", ".twig", ".php", ".j2", ".jinja", ".jinja2"}
	extWeb    = append(append([]string{}, extPy...), append(extJS, append(extRb, append(extPHP, extJVM...)...)...)...)
	extCode   = append(append([]string{}, extWeb...), extGo...)
)

// pattern is one regex of a rule. exts nil means every text file.
type pattern struct {
	rule   string
	re     *regexp.Regexp
	exts   []string
	verify func(line string) bool // optional extra filter
}

var patterns = []pattern{
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`\bverify\s*=\s*False\b`), exts: extPy},
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`rejectUnauthorized\s*:\s*false`), exts: extJS},
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`), exts: extGo},
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`VERIFY_NONE\b`), exts: extRb},
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)\b`), exts: extPHP},
	{rule: "code.tls-verify-disabled", re: regexp.MustCompile(`ALLOW_ALL_HOSTNAME_VERIFIER|TrustAllCerts|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}`), exts: extJVM},
	{rule: "code.eval-dynamic", re: regexp.MustCompile(`(^|[^\w.])(eval|exec)\s*\(`), exts: extPy},
	{rule: "code.eval-dynamic", re: regexp.MustCompile(`(^|[^\w.])eval\s*\(|new Function\s*\(`), exts: extJS},
	{rule: "code.eval-dynamic", re: regexp.MustCompile(`(^|[^\w.])eval\s*\(`), exts: append(append([]string{}, extRb...), extPHP...)},
	{rule: "code.sql-concat", re: regexp.MustCompile(`(?i)"(SELECT|INSERT|UPDATE|DELETE)\b[^"\n]*"\s*(\+|\.\s*\$|%\s*\()|'(SELECT|INSERT|UPDATE|DELETE)\b[^'\n]*'\s*(\+|\.\s*\$|%\s*\()`), exts: extCode},
	{rule: "code.sql-concat", re: regexp.MustCompile(`(?i)["'](SELECT|INSERT|UPDATE|DELETE)\b[^"']*%s[^"']*["']\s*%`), exts: extPy},
	{rule: "code.sql-concat", re: regexp.MustCompile(`(?i)\bf["'](SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{`), exts: extPy},
	{rule: "code.sql-concat", re: regexp.MustCompile("(?i)`(SELECT|INSERT|UPDATE|DELETE)\\b[^`]*\\$\\{"), exts: extJS},
	{rule: "code.sql-concat", re: regexp.MustCompile(`(?i)(Sprintf|Printf)\s*\(\s*"(SELECT|INSERT|UPDATE|DELETE)\b`), exts: extGo},
	{rule: "code.debug-true-config", re: regexp.MustCompile(`^\s*DEBUG\s*=\s*True\b`), exts: extPy},
	{rule: "code.debug-true-config", re: regexp.MustCompile(`(?i)^\s*["']?debug["']?\s*[:=]\s*["']?true\b`), exts: extConfig},
	{rule: "code.debug-true-config", re: regexp.MustCompile(`(?i)display_errors\s*[=,]\s*["']?(on|1|true)\b`), exts: extConfig},
	{rule: "code.weak-hash", re: regexp.MustCompile(`(?i)\b(md5|sha1)\b[^\n]{0,60}\b(password|passwd|pwd)\b|\b(password|passwd|pwd)\b[^\n]{0,60}\b(md5|sha1)\b`), exts: extCode},
	{rule: "code.cors-wildcard", re: regexp.MustCompile(`(?i)Access-Control-Allow-Origin["']?\s*[,:=)]\s*["']\*["']`), exts: extCode},
	{rule: "code.cors-wildcard", re: regexp.MustCompile(`(?i)\b(origin|allow_origins|AllowOrigins|CORS_ORIGIN_WHITELIST|allowedOrigins)\s*[:=]\s*\[?\s*["']\*["']`), exts: extCode},
	{rule: "code.bind-all-interfaces", re: regexp.MustCompile(`(?i)\b(bind|listen|host|HOST)\b\s*[(=:,][^\n"']{0,24}["']0\.0\.0\.0["']`), exts: extCode},
	{rule: "code.shell-injection", re: regexp.MustCompile(`subprocess\.\w+\([^)\n]*shell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\(`), exts: extPy},
	{rule: "code.shell-injection", re: regexp.MustCompile("\\bexec(Sync)?\\s*\\(\\s*`[^`]*\\$\\{|\\bexec(Sync)?\\s*\\([^)\\n]*\\+"), exts: extJS},
	{rule: "code.shell-injection", re: regexp.MustCompile(`exec\.Command(Context)?\s*\([^)\n]*"(sh|bash|/bin/sh|/bin/bash)"\s*,\s*"-c"`), exts: extGo},
	{rule: "code.shell-injection", re: regexp.MustCompile(`\b(shell_exec|passthru|system|popen|proc_open)\s*\(`), exts: extPHP},
	{rule: "code.shell-injection", re: regexp.MustCompile("(^|[^\\w])(system|exec)\\s*\\(\\s*\"[^\"]*#\\{|`[^`]*#\\{"), exts: extRb},
	{rule: "code.insecure-random-secret", re: regexp.MustCompile(`(?i)(token|secret|password|nonce|salt|session|otp)\w*\s*=[^\n]{0,60}Math\.random\s*\(`), exts: extJS},
	{rule: "code.insecure-random-secret", re: regexp.MustCompile(`(?i)(token|secret|password|nonce|salt|session|otp)\w*\s*=[^\n]{0,60}\brandom\.(random|randint|choice|choices|getrandbits)\s*\(`), exts: extPy},
	{rule: "code.weak-cipher", re: regexp.MustCompile(`(?i)(createCipheriv|createCipher|getInstance|Cipher\.new|AES\.new|DES\.new|Cipher\s*\()\s*\(?\s*["']?(des|rc4|rc2|blowfish|3des|desede|des-ede3|arcfour)[^"'\n]*["']?|["'][A-Za-z0-9]+/ECB/|MODE_ECB\b`), exts: extCode},
	{rule: "code.jwt-none-algorithm", re: regexp.MustCompile(`(?i)\balg(orithm)?s?["']?\s*[:=]\s*\[?[^\]\n]*["']none["']`), exts: extCode},
	{rule: "code.jwt-verify-disabled", re: regexp.MustCompile(`jwt\.decode\([^)\n]*verify\s*=\s*False|verify_signature["']?\s*:\s*False|ignoreExpiration\s*:\s*true|verify_exp["']?\s*:\s*False`), exts: extCode},
	{rule: "code.xxe-enabled", re: regexp.MustCompile(`disallow-doctype-decl["']?\s*,\s*false|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*true|external-general-entities["']?\s*,\s*true`), exts: extJVM},
	{rule: "code.xxe-enabled", re: regexp.MustCompile(`resolve_entities\s*=\s*True|libxml_disable_entity_loader\s*\(\s*false|LIBXML_NOENT\b`), exts: append(append([]string{}, extPy...), extPHP...)},
	{rule: "code.unsafe-deserialization", re: regexp.MustCompile(`\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\([^,)\n]*\)|\byaml\.load\s*\([^)\n]*Loader\s*=\s*yaml\.(Loader|UnsafeLoader)`), exts: extPy},
	{rule: "code.unsafe-deserialization", re: regexp.MustCompile(`\bunserialize\s*\(`), exts: extPHP},
	{rule: "code.unsafe-deserialization", re: regexp.MustCompile(`\b(Marshal\.load|YAML\.load)\s*\(?`), exts: extRb},
	{rule: "code.unsafe-deserialization", re: regexp.MustCompile(`new\s+ObjectInputStream\s*\(|XMLDecoder\s*\(`), exts: extJVM},
	{rule: "code.path-from-request", re: regexp.MustCompile(`(?i)\b(open|readFile|readFileSync|sendFile|createReadStream|os\.path\.join|path\.join|file_get_contents|include|require|fopen)\s*\([^)\n]*(req\.(query|params|body)|request\.(args|form|GET|POST|values)|\$_(GET|POST|REQUEST|FILES)|params\[)`), exts: extWeb},
	{rule: "code.unescaped-html", re: regexp.MustCompile(`dangerouslySetInnerHTML|\.innerHTML\s*=|\bv-html\s*=|bypassSecurityTrust(Html|Script|Url|ResourceUrl)|\|\s*safe\s*\}\}|\{!!|\.html\s*\(\s*(req|request|params|\$)`), exts: append(append([]string{}, extHTML...), extJS...)},
	{rule: "code.open-redirect", re: regexp.MustCompile(`(?i)\bredirect(_to)?\s*\(\s*(req\.(query|params|body)|request\.(args|form|GET|POST|values)|\$_(GET|POST|REQUEST)|params\[)`), exts: extWeb},
	{rule: "code.cookie-insecure", re: regexp.MustCompile(`(?i)\b(secure|httpOnly|httponly)\s*[:=]\s*false\b|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False`), exts: extCode},
	{rule: "code.csrf-disabled", re: regexp.MustCompile(`(?i)\bcsrf[_-]?(protection|enabled|check)?\s*[:=]\s*false\b|WTF_CSRF_ENABLED\s*=\s*False|csrf\(\)\s*\.disable\(\)|@csrf_exempt\b|protect_from_forgery\s+except`), exts: extCode},
	{rule: "code.insecure-temp-file", re: regexp.MustCompile(`["']/tmp/[A-Za-z0-9._-]+["']`), exts: extCode},
	{rule: "code.plain-http-url", re: regexp.MustCompile(`["']http://[^"'\s/]+[^"'\s]*["']`), exts: extCode, verify: notLocalOrDocHTTP},
	{rule: "code.ssrf-user-url", re: regexp.MustCompile(`(?i)\b(requests\.(get|post|put|delete|head|request)|fetch|axios(\.(get|post|put|delete))?|http\.Get|urllib\.request\.urlopen|urlopen|curl_init|file_get_contents|Net::HTTP\.get|HTTParty\.get)\s*\(\s*(req\.(query|params|body)|request\.(args|form|GET|POST|values)|\$_(GET|POST|REQUEST)|params\[)`), exts: extWeb},
	{rule: "code.sensitive-logging", re: regexp.MustCompile(`(?i)\b(console\.(log|info|debug|warn|error)|logger?\.(info|debug|warn|warning|error)|logging\.(info|debug|warning|error)|print(ln|f)?|log\.(Printf|Println|Print|Info|Debug))\s*\([^)\n]*\b\w*(password|passwd|secret|api_?key|access_?token|auth_?token|private_?key)\w*\b`), exts: extCode},
	{rule: "code.curl-pipe-shell", re: regexp.MustCompile(`\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+(-E\s+)?)?(ba|z)?sh\b`), exts: extShell},
	{rule: "code.world-writable-permissions", re: regexp.MustCompile(`\bchmod\s+(-R\s+)?0?777\b|chmod\s*\([^)\n]*0o?777\b|\b0o?777\b[^\n]{0,20}(chmod|perm|mode)|(chmod|perm|mode)[^\n]{0,20}\b0o?777\b`), exts: append(append([]string{}, extCode...), extShell...)},
	{rule: "code.timing-unsafe-compare", re: regexp.MustCompile(`(?i)\b\w*(hmac|signature|digest)\w*\s*(==|===|!=|!==)\s*\w`), exts: extCode},
	{rule: "code.legacy-tls-version", re: regexp.MustCompile(`\b(TLSv1\b|TLSv1_0|TLSv1_1|TLS1_0|TLS1_1|SSLv3|SSLv2|PROTOCOL_TLSv1(_1)?\b|PROTOCOL_SSLv23|PROTOCOL_SSLv3|tls\.VersionTLS10|tls\.VersionTLS11|tls\.VersionSSL30|TLSv1\.0|TLSv1\.1)\b|minVersion\s*:\s*["']TLSv1(\.1)?["']`), exts: extCode},
	{rule: "code.graphql-introspection", re: regexp.MustCompile(`\bintrospection\s*:\s*true\b`), exts: extJS},
	{rule: "code.docker-socket-mount", re: regexp.MustCompile(`/var/run/docker\.sock`), exts: []string{".yml", ".yaml", ".json", ".toml"}},
	{rule: "code.allowed-hosts-wildcard", re: regexp.MustCompile(`ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']`), exts: extPy},
}

var httpExcluded = []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "example.", "schemas.", "www.w3.org", "xmlns", "json-schema.org", "purl.org", "ns.adobe.com", "openrdf.org", "apache.org/licenses", "www.apple.com/DTDs", "maven.apache.org", "java.sun.com", "xmlsoap.org", "docs.oasis-open.org", "activemq.apache.org/schema", "springframework.org/schema"}

// notLocalOrDocHTTP keeps only http URLs that are not loopback, examples,
// or XML namespaces/schemas (RE2 has no lookahead, so this is a filter).
func notLocalOrDocHTTP(line string) bool {
	l := strings.ToLower(line)
	for _, x := range httpExcluded {
		if strings.Contains(l, "http://"+x) || strings.Contains(l, "http://www."+x) {
			return false
		}
	}
	return true
}

// Engine implements engine.Engine.
type Engine struct {
	rules engine.RuleSet
}

// New loads the rule prose and checks every pattern has a rule.
func New() (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	for _, p := range patterns {
		rs.MustGet(p.rule)
	}
	return &Engine{rules: rs}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Supports path targets.
func (e *Engine) Supports(t domain.Target) bool { return t.Type == domain.TargetPath }

// RuleCount is the number of distinct rules.
func RuleCount() int {
	seen := map[string]bool{}
	for _, p := range patterns {
		seen[p.rule] = true
	}
	return len(seen)
}

// Plan implements engine.Engine.
func (e *Engine) Plan(ctx context.Context, t domain.Target, _ engine.Options) (engine.Plan, error) {
	st, err := engine.WalkFiles(ctx, t.Value, func(string, []byte) error { return nil })
	if err != nil {
		return engine.Plan{}, err
	}
	return engine.Plan{Summary: fmt.Sprintf("%d text files checked against %d pattern-grade rules (tentative; verify in context)", st.Files, RuleCount()),
		EstDuration: time.Duration(st.Files/100+1) * time.Second}, nil
}

// Run implements engine.Engine.
func (e *Engine) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	red := o.Redactor
	if red == nil {
		red = safety.NewRedactor()
	}
	assetKey := t.AssetKey()
	_, err := engine.WalkFiles(ctx, t.Value, func(rel string, content []byte) error {
		for _, m := range ScanContent(rel, content) {
			loc := fmt.Sprintf("%s:%d", rel, m.Line)
			f := e.rules.NewFinding(m.Rule, assetKey, loc, domain.Tentative)
			f.WhatItIs += " " + VerifyText
			f.Evidence = []domain.Evidence{red.TextEvidence("file", loc, m.Excerpt)}
			if err := emit(f); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// Match is one pattern hit.
type Match struct {
	Rule    string
	Line    int
	Excerpt string
}

func applies(p pattern, rel string) bool {
	if p.exts == nil {
		return true
	}
	base := path.Base(rel)
	ext := strings.ToLower(path.Ext(base))
	for _, e := range p.exts {
		if e == ext || e == base {
			return true
		}
	}
	return false
}

// ScanContent runs every applicable pattern over content. Exported for
// tests and fuzzing. One finding per (rule, line).
func ScanContent(rel string, content []byte) []Match {
	var active []pattern
	for _, p := range patterns {
		if applies(p, rel) {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil
	}
	var out []Match
	seen := map[string]bool{}
	line := 0
	for _, l := range strings.Split(string(content), "\n") {
		line++
		if len(l) > maxLineBytes {
			l = l[:maxLineBytes]
		}
		trim := strings.TrimSpace(l)
		if trim == "" || strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "*") {
			continue // comments: a pattern in a comment is not code
		}
		for _, p := range active {
			if !p.re.MatchString(l) || (p.verify != nil && !p.verify(l)) {
				continue
			}
			k := p.rule + "\x00" + fmt.Sprint(line)
			if seen[k] {
				continue
			}
			seen[k] = true
			ex := trim
			if len(ex) > 300 {
				ex = ex[:300]
			}
			out = append(out, Match{Rule: p.rule, Line: line, Excerpt: ex})
			if len(out) >= maxMatchesPerFile {
				return out
			}
		}
	}
	return out
}
