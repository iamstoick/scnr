package safety

import (
	"strings"
	"testing"
)

// Every refusal a newcomer can hit must explain the problem in plain
// English and name a concrete next step. The machine code stays as a
// footnote, never as the headline.
func TestRefusalFriendlyGuidesUser(t *testing.T) {
	cases := []struct {
		code   string
		target string
		reason string
		// Each must appear (case-insensitive for the guidance line).
		want []string
	}{
		{CodeScopeNotAllowed, "geraldvillorente.com", "public address not in scope.allow",
			[]string{"approved list", "scnr.yaml", "scnr scope check geraldvillorente.com", "scnr verify", "E_SCOPE_NOT_ALLOWED", "What to do next"}},
		{CodeScopeNotAllowed, "203.0.113.0/24", "public range not fully covered by scope.allow",
			[]string{"approved list", "scnr scope check", "E_SCOPE_NOT_ALLOWED"}},
		{CodeScopeDenied, "denied.test", "matches deny entry denied.test",
			[]string{"block list", "scope.deny", "scnr scope check", "E_SCOPE_DENIED"}},
		{CodeAckRequired, "10.0.0.1", "authorization not acknowledged",
			[]string{"--ack-authorized", "scnr scope init", "E_ACK_REQUIRED"}},
		{CodeOwnershipRequired, "public.test", "public target requires ownership verification",
			[]string{"ownership", "scnr verify public.test", "E_OWNERSHIP_REQUIRED"}},
		{CodeOwnershipRequired, "203.0.113.10", "bare public IPs can only be verified via the well-known file",
			[]string{"well-known", "scnr verify", "E_OWNERSHIP_REQUIRED"}},
		{CodeCloudAccountNotAllowed, "aws://audit", "account 123456789012 is not in cloud.aws.accounts",
			[]string{"cloud.aws.accounts", "E_CLOUD_ACCOUNT_NOT_ALLOWED"}},
		{CodeCIDRTooLarge, "10.0.0.0/15", "131072 hosts exceeds cap of 65536; pass --max-hosts 131072 to override (audited)",
			[]string{"--max-hosts", "E_CIDR_TOO_LARGE"}},
		{CodeConsentDeclined, "public.test", "consent not given",
			[]string{"confirm", "E_CONSENT_DECLINED"}},
		{CodeUnresolvable, "typo.invalid", "no such host",
			[]string{"spelling", "scnr scope check", "E_UNRESOLVABLE"}},
		{CodeUnresolvable, "10.0.0.0/99", "bad CIDR",
			[]string{"10.0.0.0/24", "E_UNRESOLVABLE"}},
		{CodeBundleUntrusted, "bundle.tar.gz", "no trusted key verified the signature",
			[]string{"vulndb.trusted_keys", "scnr db bundle verify", "E_BUNDLE_UNTRUSTED"}},
		{CodeBundleDowngrade, "bundle.tar.gz", "bundle created_at 2024-01-01 is older than the loaded osv-offline data",
			[]string{"--allow-downgrade", "E_BUNDLE_DOWNGRADE"}},
		{CodeEndpointPrivate, "api.example.com", "resolves to a non-public address",
			[]string{"public endpoint", "E_ENDPOINT_PRIVATE"}},
		{CodeCloudCredentialSource, "aws://", "no credentials found",
			[]string{"scnr doctor", "E_CLOUD_CREDENTIAL_SOURCE"}},
		{CodeCloudIdentity, "aws://", "could not confirm the account",
			[]string{"sts:GetCallerIdentity", "E_CLOUD_IDENTITY"}},
		{CodeLimitTooHigh, "rate", "1000 exceeds 2x default",
			[]string{"--i-understand-rate-limits", "E_LIMIT_TOO_HIGH"}},
	}
	for _, c := range cases {
		t.Run(c.code+"/"+c.target, func(t *testing.T) {
			got := (&RefusalError{Code: c.code, Target: c.target, Reason: c.reason}).Friendly()
			if strings.HasPrefix(got, "E_") || strings.HasPrefix(got, c.code) {
				t.Fatalf("friendly message must not lead with the code:\n%s", got)
			}
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("friendly %s %q missing %q:\n%s", c.code, c.target, w, got)
				}
			}
		})
	}
}

// A URL target suggests the bare host for allow/verify examples, not the full URL.
func TestRefusalFriendlyURLTargetUsesHost(t *testing.T) {
	got := (&RefusalError{Code: CodeScopeNotAllowed, Target: "https://app.example.com/", Reason: "public address not in scope.allow"}).Friendly()
	if !strings.Contains(got, "- app.example.com") || !strings.Contains(got, "scnr verify app.example.com") {
		t.Fatalf("URL target should suggest the bare host:\n%s", got)
	}
	if strings.Contains(got, "scnr verify https://") {
		t.Fatalf("verify example must not be a URL:\n%s", got)
	}
}
