package safety

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
)

// Redactor masks secret-looking values in free text. It is applied to log
// lines, adapter output and any evidence before a domain.Evidence is built.
type Redactor struct {
	patterns []*regexp.Regexp
}

// secretKeyNames are the key names (optionally prefixed, as in
// "db_password" or "SecretAccessKey") whose quoted value is a secret in
// JSON/YAML-shaped text: {"password": "..."} or 'api_key': '...'.
const secretKeyNames = `[a-z0-9_.-]{0,40}(?:password|passwd|pwd|secret|api[_-]?key|token|authorization|access[_-]?key|client[_-]?secret|private[_-]?key)`

// quotedKeyRe matches a quoted key followed by ':' and a quoted value; the
// value may contain backslash-escaped quotes. Groups: 1 = key and colon,
// 2 = a double-quoted value, 3 = a single-quoted value (exactly one of 2/3
// matches). RE2: linear time, no backtracking.
var quotedKeyRe = regexp.MustCompile(`(?i)(["'](?:` + secretKeyNames + `)["']\s*:\s*)(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)

// Known credential shapes. Kept deliberately broad: a false positive in a
// log line costs nothing; a missed secret in a report is unacceptable.
var defaultPatterns = []string{
	`AKIA[0-9A-Z]{16}`, // AWS access key id
	`ASIA[0-9A-Z]{16}`, // AWS temp key id
	`(?i)aws(.{0,20})?(secret|private)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`, // AWS secret
	`ghp_[A-Za-z0-9]{36}`,                                           // GitHub PAT
	`github_pat_[A-Za-z0-9_]{22,}`,                                  // GitHub fine-grained PAT
	`gho_[A-Za-z0-9]{36}`,                                           // GitHub OAuth
	`glpat-[A-Za-z0-9\-_]{20,}`,                                     // GitLab PAT
	`xox[baprs]-[A-Za-z0-9-]{10,}`,                                  // Slack tokens
	`https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+`,            // Slack webhooks
	`sk_(live|test)_[A-Za-z0-9]{10,}`,                               // Stripe
	`rk_(live|test)_[A-Za-z0-9]{10,}`,                               // Stripe restricted
	`SK[0-9a-fA-F]{32}`,                                             // Twilio
	`AIza[0-9A-Za-z\-_]{35}`,                                        // Google API key
	`ya29\.[0-9A-Za-z\-_]+`,                                         // Google OAuth access token
	`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, // JWT
	`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`,
	`(?i)(password|passwd|pwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*['"]?[^\s'"]{6,}`,
	`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`,
	`(?i)[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`, // user:pass@ in URLs
}

// NewRedactor builds the default redactor.
func NewRedactor() *Redactor {
	r := &Redactor{}
	for _, p := range defaultPatterns {
		r.patterns = append(r.patterns, regexp.MustCompile(p))
	}
	return r
}

// Redact masks every match in s using Mask.
func (r *Redactor) Redact(s string) string {
	if s == "" {
		return s
	}
	s = redactQuotedKeys(s)
	for _, re := range r.patterns {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			if strings.Contains(m, "://") && strings.HasSuffix(m, "@") {
				// scheme://user:pass@ -> scheme://user:***@
				at := strings.LastIndex(m, ":")
				return m[:at+1] + "***@"
			}
			// For key=value matches keep the key visible.
			if i := strings.IndexAny(m, ":="); i > 0 && i < 24 && !strings.HasPrefix(strings.ToLower(m), "bearer") {
				return m[:i+1] + Mask(strings.TrimLeft(m[i+1:], " \t'\""))
			}
			return Mask(m)
		})
	}
	return s
}

// redactQuotedKeys masks the value of every quoted secret key in s (JSON,
// YAML flow style, JS object literals), keeping the key and the quotes
// visible: {"password": "hunter2-not-a-real-pw"} -> {"password": "hu************w"}.
func redactQuotedKeys(s string) string {
	idx := quotedKeyRe.FindAllStringSubmatchIndex(s, -1)
	if len(idx) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, m := range idx {
		prefixEnd := m[3]
		valStart, valEnd, quote := m[4], m[5], `"`
		if valStart < 0 {
			valStart, valEnd, quote = m[6], m[7], `'`
		}
		b.WriteString(s[last:prefixEnd])
		b.WriteString(quote)
		b.WriteString(Mask(s[valStart:valEnd]))
		b.WriteString(quote)
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// Mask masking budget: never reveal more than a quarter of the value and at
// most MaskMaxReveal characters; values shorter than MaskShortLen reveal at
// most 2, and anything under 8 characters is masked entirely. Enough to
// recognise a key prefix, not enough to recover a password.
const (
	MaskMaxReveal = 6
	MaskShortLen  = 16
)

// Mask keeps a length-aware prefix (and, for long values, a 1-2 character
// suffix) of a secret and masks the rest. Short values are fully masked.
func Mask(raw string) string {
	raw = strings.TrimSpace(raw)
	n := len(raw)
	if n < 8 {
		return strings.Repeat("*", n)
	}
	reveal := 2
	if n >= MaskShortLen {
		reveal = n / 4
		if reveal > MaskMaxReveal {
			reveal = MaskMaxReveal
		}
	}
	suffix := reveal / 3 // 0 for short values, 1-2 for long ones
	prefix := reveal - suffix
	masked := n - reveal
	if masked > 12 {
		masked = 12 // keep output short; the run of '*' conveys elision
	}
	return raw[:prefix] + strings.Repeat("*", masked) + raw[n-suffix:]
}

// SecretHash fingerprints a raw secret with HMAC-SHA256 under the
// per-install key (LoadOrCreateSecret). A plain digest would let anyone
// holding the report confirm a guessed password offline; the keyed form is
// still stable across re-scans on the same install.
func SecretHash(key []byte, raw string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(raw))
	return hex.EncodeToString(m.Sum(nil))
}

// SecretEvidence builds Evidence for a raw secret: masked form plus the
// keyed fingerprint. The raw value does not escape this function.
func SecretEvidence(key []byte, kind, location, raw string) domain.Evidence {
	return domain.Evidence{
		Kind:     kind,
		Location: location,
		Redacted: Mask(raw),
		Hash:     SecretHash(key, raw),
	}
}

// Clean trims, strips control characters, caps at max bytes and redacts a
// string from an untrusted source (tool output, lockfile, image contents).
func (r *Redactor) Clean(s string, max int) string {
	s = strings.TrimSpace(StripControl(s))
	if len(s) > max {
		s = s[:max]
	}
	return r.Redact(s)
}

// TextEvidence builds Evidence for a non-secret excerpt (banner, header,
// response), running the redactor over it and capping its size.
func (r *Redactor) TextEvidence(kind, location, raw string) domain.Evidence {
	red := r.Redact(StripControl(raw))
	if len(red) > domain.MaxEvidenceBytes {
		red = red[:domain.MaxEvidenceBytes]
	}
	return domain.Evidence{Kind: kind, Location: location, Redacted: red, Hash: domain.SHA256Hex(raw)}
}

// StripControl removes control characters except tab and newline so hostile
// banners/tool output cannot corrupt terminals or reports.
func StripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
