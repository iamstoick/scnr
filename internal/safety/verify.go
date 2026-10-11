package safety

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/store"
)

// Verification constants (Section 9).
const (
	VerifyTXTPrefix     = "_scnr-verify."
	VerifyWellKnownPath = "/.well-known/scnr-verify.txt"
	VerifyRecordPrefix  = "scnr-verify="
	VerifyTTL           = 30 * 24 * time.Hour
	SecretFile          = "secret"
)

// LoadOrCreateSecret returns the local HMAC secret from <home>/secret,
// creating it with 0600 if absent.
func LoadOrCreateSecret(home string) ([]byte, error) {
	p := filepath.Join(home, SecretFile)
	b, err := os.ReadFile(p)
	if err == nil && len(b) >= 32 {
		return b, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("write %s: %w", p, err)
	}
	return b, nil
}

// Token derives the deterministic verification token for host.
func Token(secret []byte, host string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(strings.ToLower(strings.TrimSuffix(host, "."))))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(m.Sum(nil))
	return strings.ToLower(enc[:32])
}

// TXTResolver is the DNS TXT lookup the verifier needs.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Verifier checks and records ownership proofs.
type Verifier struct {
	Store  *store.Store
	Secret []byte
	TXT    TXTResolver
	HTTP   *http.Client // must be a scope-checked client
	Now    func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Check verifies host via DNS TXT then the well-known file, and stores a
// 30-day verification on success. Bare IPs only use the well-known path.
func (v *Verifier) Check(ctx context.Context, host string) (method string, err error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	want := Token(v.Secret, host)
	isIP := false
	if _, perr := netip.ParseAddr(host); perr == nil {
		isIP = true
	}
	var errs []string
	if !isIP && v.TXT != nil {
		ok, derr := v.checkTXT(ctx, host, want)
		if ok {
			method = domain.ConsentDNSTXT
		} else if derr != nil {
			errs = append(errs, "dns: "+derr.Error())
		} else {
			errs = append(errs, "dns: no matching TXT record")
		}
	}
	if method == "" && v.HTTP != nil {
		ok, herr := v.checkWellKnown(ctx, host, want)
		if ok {
			method = domain.ConsentWellKnown
		} else if herr != nil {
			errs = append(errs, "well-known: "+herr.Error())
		} else {
			errs = append(errs, "well-known: token not found")
		}
	}
	if method == "" {
		return "", fmt.Errorf("verification failed for %s (%s)", host, strings.Join(errs, "; "))
	}
	now := v.now()
	if err := v.Store.PutVerification(ctx, store.Verification{Host: host, Method: method, VerifiedAt: now, ExpiresAt: now.Add(VerifyTTL)}); err != nil {
		return "", err
	}
	return method, nil
}

func (v *Verifier) checkTXT(ctx context.Context, host, want string) (bool, error) {
	recs, err := v.TXT.LookupTXT(ctx, VerifyTXTPrefix+host)
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if strings.TrimSpace(r) == VerifyRecordPrefix+want {
			return true, nil
		}
	}
	return false, nil
}

func (v *Verifier) checkWellKnown(ctx context.Context, host, want string) (bool, error) {
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+VerifyWellKnownPath, nil)
		if err != nil {
			return false, err
		}
		resp, err := v.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := ReadBody(resp, 4096)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: HTTP %d", scheme, resp.StatusCode)
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			if strings.TrimSpace(line) == VerifyRecordPrefix+want {
				return true, nil
			}
		}
		return false, nil
	}
	return false, lastErr
}

// IsVerified reports whether host (or, via DNS TXT, a parent domain above
// the public suffix) has a non-expired verification.
func (v *Verifier) IsVerified(ctx context.Context, host string) (bool, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	now := v.now()
	rec, err := v.Store.GetVerification(ctx, host)
	if err == nil && rec.ExpiresAt.After(now) {
		return true, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		return false, nil // no parent-domain walk for IPs
	}
	// Walk parents down to eTLD+1; only DNS verifications cover subdomains.
	apex, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return false, nil
	}
	for h := host; h != apex && strings.Contains(h, "."); {
		h = h[strings.Index(h, ".")+1:]
		rec, err := v.Store.GetVerification(ctx, h)
		if err == nil && rec.Method == domain.ConsentDNSTXT && rec.ExpiresAt.After(now) {
			return true, nil
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return false, err
		}
		if len(h) <= len(apex) {
			break
		}
	}
	return false, nil
}
