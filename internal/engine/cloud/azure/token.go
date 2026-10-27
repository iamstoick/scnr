package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenSource mints ARM bearer tokens. Only two implementations exist:
// client-secret (environment service principal) and managed identity
// (opt-in). Nothing interactive, no browser, no shared cache.
type tokenSource interface {
	Token(ctx context.Context) (string, error)
}

// clientSecretCredential is an OAuth2 client-credentials login against
// Entra ID. The secret travels in exactly one POST body and never in an
// error, a log, or a finding.
type clientSecretCredential struct {
	client   *http.Client
	tokenURL string
	clientID string
	tenantID string
	secret   string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (c *clientSecretCredential) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiry) > 5*time.Minute {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {TokenScope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("entra token request failed: %w", sanitizeTokenError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("entra token response unreadable (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("entra token request refused (HTTP %d)", resp.StatusCode)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.AccessToken == "" {
		return "", fmt.Errorf("entra token response malformed")
	}
	c.token = got.AccessToken
	c.expiry = time.Now().Add(time.Duration(got.ExpiresIn) * time.Second)
	return c.token, nil
}

// managedIdentityCredential uses the VM identity endpoint. It only exists
// when the scope file opts in; without that, the address is never dialed.
type managedIdentityCredential struct {
	client   *http.Client
	endpoint string
	resource string

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (c *managedIdentityCredential) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.expiry) > 5*time.Minute {
		return c.token, nil
	}
	u := c.endpoint + "/metadata/identity/oauth2/token?api-version=2019-08-01&resource=" + url.QueryEscape(c.resource)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("managed identity endpoint unreachable: %w", sanitizeTokenError(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("managed identity refused (HTTP %d)", resp.StatusCode)
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresOn   string `json:"expires_on"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.AccessToken == "" {
		return "", fmt.Errorf("managed identity response malformed")
	}
	exp := time.Now().Add(time.Hour)
	if epoch, err := strconv.ParseInt(strings.TrimSpace(got.ExpiresOn), 10, 64); err == nil {
		exp = time.Unix(epoch, 0)
	} else if t, err := time.Parse(time.RubyDate, got.ExpiresOn); err == nil {
		exp = t
	}
	c.token, c.expiry = got.AccessToken, exp
	return c.token, nil
}

// sanitizeTokenError strips any value that could carry the secret: only
// the error kind travels, never the message.
func sanitizeTokenError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("request failed")
}
