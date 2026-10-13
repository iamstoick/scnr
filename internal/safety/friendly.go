// Friendly refusal messages: plain-English explanations with next steps.
//
// RefusalError.Error stays machine-readable (CODE: target: reason) for the
// audit trail and exit-code mapping. Friendly is what people see on stderr:
// what happened, why scnr stopped, and exactly what to do next. Every
// message ends with the code in parentheses so support and tests can still
// match it, but the code is never the first thing a newcomer reads.
package safety

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// Friendly returns a plain-English explanation of the refusal with concrete
// next steps. It never includes credentials: callers redact the result the
// same way they redact Error.
func (e *RefusalError) Friendly() string {
	if e == nil {
		return ""
	}
	target := e.Target
	if target == "" {
		target = "this target"
	}
	var msg string
	switch e.Code {
	case CodeScopeNotAllowed:
		msg = friendlyScopeNotAllowed(target, e.Reason)
	case CodeScopeDenied:
		msg = fmt.Sprintf("Couldn't scan %s: it's on your block list (%s).\n\n"+
			"scnr never scans anything on the block list — blocking always wins, even when the address is also approved.\n\n"+
			"What to do next:\n"+
			"  1. If you meant to block it, pick a different target.\n"+
			"  2. If it should be scannable, open scnr.yaml and remove the matching entry from scope.deny.\n"+
			"  3. Check it with: scnr scope check %s, then re-run your scan.",
			target, e.Reason, target)
	case CodeAckRequired:
		msg = "Couldn't start: you haven't confirmed you're allowed to scan yet.\n\n" +
			"scnr needs your explicit confirmation before touching any target.\n\n" +
			"What to do next (pick one):\n" +
			"  1. Add --ack-authorized to this scan, or\n" +
			"  2. Save it once with: scnr scope init"
	case CodeOwnershipRequired:
		msg = friendlyOwnershipRequired(target, e.Reason)
	case CodeCloudAccountNotAllowed:
		msg = fmt.Sprintf("Couldn't scan %s: this AWS account isn't on your approved accounts list yet.\n\n"+
			"What to do next (pick one):\n"+
			"  1. Open scnr.yaml and add the 12-digit account ID to cloud.aws.accounts, then re-run.\n"+
			"  2. Or run the same scan interactively (no --non-interactive) and type the account ID back when asked.\n"+
			"Details: %s.",
			target, e.Reason)
	case CodeCIDRTooLarge:
		msg = fmt.Sprintf("Couldn't scan %s: it's a large network range (%s).\n\n"+
			"scnr caps how many addresses one scan covers, so a typo doesn't turn into a huge scan.\n\n"+
			"What to do next (pick one):\n"+
			"  1. Scan a smaller range (for example, split it into /24 pieces).\n"+
			"  2. Or, if you really mean the whole range, approve it with --max-hosts (this is recorded in the audit log).\n"+
			"     Example: scnr scan %s --max-hosts <count> --ack-authorized",
			target, e.Reason, target)
	case CodeConsentDeclined:
		msg = fmt.Sprintf("Scan cancelled: you didn't confirm ownership when asked.\n\n"+
			"What to do next:\n"+
			"  1. Re-run the same scan.\n"+
			"  2. When asked, type %s exactly to confirm you own it (or anything else to cancel).",
			target)
	case CodeUnresolvable:
		msg = friendlyUnresolvable(target, e.Reason)
	case CodeBundleUntrusted:
		msg = friendlyBundleUntrusted(target, e.Reason)
	case CodeBundleDowngrade:
		msg = fmt.Sprintf("Couldn't load %s: it's older than the vulnerability data you already have, so loading it would roll you back.\n\n"+
			"What to do next (pick one):\n"+
			"  1. Get a newer bundle and load that instead.\n"+
			"  2. If you really want the older data and you're at a terminal, re-run with --allow-downgrade (recorded in the audit log).\n"+
			"Details: %s.",
			target, e.Reason)
	case CodeEndpointPrivate:
		msg = fmt.Sprintf("Blocked a request to %s: it resolved to a private address, but this cloud service needs its public address.\n\n"+
			"Private (PrivateLink/VPC) endpoints aren't supported.\n\n"+
			"What to do next:\n"+
			"  1. Use the service's public endpoint instead.\n"+
			"  2. Check your DNS or VPN — you may be resolving the public name to a private address.\n"+
			"Details: %s.",
			target, e.Reason)
	case CodeCloudCredentialSource:
		msg = fmt.Sprintf("Couldn't access AWS for %s: %s.\n\n"+
			"What to do next:\n"+
			"  1. Follow the hint above (set the missing environment variables or profile).\n"+
			"  2. Run `scnr doctor` to see which credential source scnr would use.\n"+
			"  3. Re-run your scan.",
			target, e.Reason)
	case CodeCloudIdentity:
		msg = fmt.Sprintf("Couldn't confirm which AWS account your credentials belong to (%s).\n\n"+
			"scnr checks this before touching anything, so you never scan the wrong account.\n\n"+
			"What to do next:\n"+
			"  1. Check your credentials and network, then try again.\n"+
			"  2. Make sure they allow sts:GetCallerIdentity.\n"+
			"  3. Run `scnr doctor` to see the credential source.\n"+
			"Details: %s.",
			target, e.Reason)
	case CodeLimitTooHigh:
		msg = fmt.Sprintf("Couldn't start: the requested %s (%s) is above the safe ceiling.\n\n"+
			"What to do next (pick one):\n"+
			"  1. Lower it (lowering is always allowed).\n"+
			"  2. Or, if you understand the impact, add --i-understand-rate-limits (recorded in the audit log).",
			target, e.Reason)
	default:
		msg = fmt.Sprintf("Couldn't continue with %s: %s.\n\n"+
			"What to do next:\n"+
			"  1. Run `scnr doctor` to check your setup.\n"+
			"  2. Run `scnr scope check %s` if this was a scan target.",
			target, e.Reason, target)
	}
	return msg + fmt.Sprintf("\n(code %s)", e.Code)
}

func friendlyScopeNotAllowed(target, reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "public range not fully"):
		return fmt.Sprintf("Couldn't scan %s: it's a public network range that isn't fully on your approved list yet.\n\n"+
			"scnr only scans public ranges you've explicitly approved, so you don't accidentally scan someone else's network.\n\n"+
			"What to do next:\n"+
			"  1. Open scnr.yaml and add the exact range to your approved list:\n"+
			"       scope:\n"+
			"         allow:\n"+
			"           - %s\n"+
			"     (Run `scnr scope init` first if you don't have a scnr.yaml yet.)\n"+
			"  2. Check it with: scnr scope check %s\n"+
			"  3. Re-run without --non-interactive and confirm when asked — public ranges always need that interactive confirmation.",
			target, target, target)
	case strings.Contains(lower, "dns answer changed") || strings.Contains(lower, "possible rebinding"):
		return fmt.Sprintf("Stopped while scanning %s: its internet address changed mid-scan, so scnr stopped to stay safe.\n\n"+
			"This is usually a brief network hiccup.\n\n"+
			"What to do next:\n"+
			"  1. Wait a moment and re-run the same scan.\n"+
			"  2. If it keeps happening, check your network or VPN and that the address for %s is stable.\n"+
			"  3. Run `scnr scope check %s` to see the current decision.\n"+
			"Details: %s.",
			target, target, target, reason)
	case strings.Contains(lower, "non-public address") && strings.Contains(lower, "public-target"):
		return fmt.Sprintf("Blocked part of the scan for %s: it tried to send scnr to a private (home/office network) address, which isn't allowed during a public scan.\n\n"+
			"This protects your local network.\n\n"+
			"What to do next:\n"+
			"  1. If you meant to scan that private address, scan it directly instead.\n"+
			"  2. Otherwise no action is needed — scnr skipped only the unsafe redirect.\n"+
			"Details: %s.",
			target, reason)
	case strings.Contains(lower, "public address during a private-scope scan"):
		return fmt.Sprintf("Couldn't reach %s: it turned out to be a public internet address, but this scan was set up for private addresses only.\n\n"+
			"What to do next:\n"+
			"  1. Check the address for typos.\n"+
			"  2. If it really is public, approve it first (run `scnr scope check %s`) and prove ownership with `scnr verify`.\n"+
			"  3. Re-run the scan.",
			target, target)
	case strings.Contains(lower, "not a declared endpoint host"):
		return fmt.Sprintf("Blocked a request to %s: it isn't one of the service addresses scnr is allowed to contact.\n\n"+
			"What to do next:\n"+
			"  1. Run `scnr doctor` to check your setup.\n"+
			"  2. If this keeps happening, report the step you were doing and this message.",
			target)
	default:
		host := displayHost(target)
		allowEntry := host
		verifyExample := fmt.Sprintf("scnr verify %s\n            scnr verify %s --check", host, host)
		// A bare public IP can't use DNS verification; point at the file or interactive consent.
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
			verifyExample = fmt.Sprintf("Publish the token file at https://%s/.well-known/scnr-verify.txt (get the token with `scnr verify %s`), then run:\n"+
				"            scnr verify %s --check",
				host, host, host)
		}
		return fmt.Sprintf("Couldn't scan %s: it's a public internet address, but it isn't on your approved list yet.\n\n"+
			"scnr only scans public addresses you've explicitly approved, so you don't accidentally scan someone else's system.\n\n"+
			"What to do next:\n"+
			"  1. Open scnr.yaml (run `scnr scope init` if you don't have one yet) and add it to your approved list:\n"+
			"       scope:\n"+
			"         allow:\n"+
			"           - %s\n"+
			"  2. Check it with: scnr scope check %s\n"+
			"  3. Then prove you own it (one-time setup, valid 30 days):\n"+
			"            %s\n"+
			"     Or run the scan interactively (without --non-interactive) and confirm when asked.\n"+
			"  4. Re-run your scan.",
			target, allowEntry, target, verifyExample)
	}
}

func friendlyOwnershipRequired(target, reason string) string {
	host := displayHost(target)
	if strings.Contains(strings.ToLower(reason), "bare public ip") {
		return fmt.Sprintf("Couldn't scan %s yet: it's approved, but scnr still needs proof you own it (ownership verification).\n\n"+
			"Bare public IPs can't use DNS verification.\n\n"+
			"What to do next (pick one):\n"+
			"  1. Publish the token file at https://%s/.well-known/scnr-verify.txt, then run: scnr verify %s --check\n"+
			"     (Get the token with: scnr verify %s)\n"+
			"  2. Or run the same scan interactively (without --non-interactive) and type %s back when asked.",
			target, host, host, host, target)
	}
	return fmt.Sprintf("Couldn't scan %s yet: it's approved, but scnr still needs proof you own it (ownership verification).\n\n"+
		"What to do next (pick one):\n"+
		"  1. Prove ownership once (valid 30 days):\n"+
		"       scnr verify %s\n"+
		"       scnr verify %s --check\n"+
		"  2. Or run the same scan interactively (without --non-interactive) and type %s back when asked.",
		target, host, host, target)
}

func friendlyUnresolvable(target, reason string) string {
	if reason == "bad CIDR" || strings.Contains(target, "/") {
		return fmt.Sprintf("Couldn't scan %s: it doesn't look like a valid network range.\n\n"+
			"What to do next:\n"+
			"  1. Check the format — it should look like 10.0.0.0/24.\n"+
			"  2. Run `scnr scope check %s` to test it, then re-run your scan.",
			target, target)
	}
	if reason == "no addresses" {
		return fmt.Sprintf("Couldn't find %s: it didn't resolve to any address.\n\n"+
			"What to do next:\n"+
			"  1. Check the spelling.\n"+
			"  2. Check your network or VPN, then try again.\n"+
			"  3. Run `scnr scope check %s` to see what scnr makes of it.",
			target, target)
	}
	return fmt.Sprintf("Couldn't find %s: scnr couldn't look it up.\n\n"+
		"What to do next:\n"+
		"  1. Check the spelling.\n"+
		"  2. Check your network or VPN, then try again.\n"+
		"  3. If it's a file or folder, make sure the path exists (or pass --type path). If it's a container image, pass --type image.\n"+
		"  4. Run `scnr scope check %s` to see what scnr makes of it.\n"+
		"Details: %s.",
		target, target, reason)
}

func friendlyBundleUntrusted(target, reason string) string {
	if strings.Contains(strings.ToLower(reason), "interactive session") {
		return fmt.Sprintf("Couldn't load %s without asking you first: --allow-unsigned needs an interactive terminal.\n\n"+
			"What to do next:\n"+
			"  1. Re-run the same command at a terminal (no --non-interactive, not from the daemon) with --allow-unsigned.\n"+
			"  2. Or load a signed bundle from a trusted key instead.\n"+
			"Details: %s.",
			target, reason)
	}
	return fmt.Sprintf("Couldn't load %s: its signature isn't from a key you trust.\n\n"+
		"scnr only loads vulnerability data from sources you've approved.\n\n"+
		"What to do next (pick one):\n"+
		"  1. Add the builder's public key to vulndb.trusted_keys in scnr.yaml (from `scnr db keygen` on the builder machine), then retry.\n"+
		"  2. Inspect it first with: scnr db bundle verify %s\n"+
		"  3. If you trust this file and you're at a terminal, re-run with --allow-unsigned (recorded in the audit log).\n"+
		"Details: %s.",
		target, target, reason)
}

// displayHost extracts a bare hostname from a URL target for verify/allow
// examples; anything else is returned unchanged.
func displayHost(target string) string {
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return target
}
