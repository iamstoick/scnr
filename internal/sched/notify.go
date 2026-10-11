package sched

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/safety"
)

// Notify tuning: attempts, timeout, and the response cap.
const (
	notifyAttempts = 3
	notifyTimeout  = 30 * time.Second
	notifyBodyCap  = 64 << 10
)

// Notifier POSTs run summaries to a webhook. The body carries counts and
// metadata only — never findings or evidence. Delivery goes through the
// endpoint client pinned to the single notify host: metadata endpoints
// are denied, redirects are never followed, and the URL (which may carry
// a token in path or query) never appears in errors, logs, or audit rows.
type Notifier struct {
	URL  *url.URL
	HTTP *http.Client
	Log  *slog.Logger

	// Attempts overrides notifyAttempts; Backoff computes the sleep
	// before retry n (0-based); BodyCap overrides notifyBodyCap.
	// Tests set Attempts: 1 and a zero Backoff.
	Attempts int
	Backoff  func(retry int) time.Duration
	BodyCap  int64
}

// NewNotifier validates rawURL and builds the pinned client. Only
// https:// is accepted, plus http:// to loopback for local relays.
func NewNotifier(rawURL string, log *slog.Logger) (*Notifier, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("notify: bad URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("notify: http:// is only allowed to loopback hosts")
		}
	default:
		return nil, fmt.Errorf("notify: URL must be https:// (http:// only to loopback)")
	}
	if u.User != nil {
		return nil, fmt.Errorf("notify: URL must not carry credentials")
	}
	hc, err := safety.NewEndpointClientPolicy([]string{u.Hostname()},
		safety.HTTPOptions{Timeout: notifyTimeout, UserAgent: "scnr-daemon"},
		safety.EndpointPolicy{RefuseRedirects: true})
	if err != nil {
		return nil, fmt.Errorf("notify: %w", err)
	}
	return &Notifier{URL: u, HTTP: hc, Log: log}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (n *Notifier) attempts() int {
	if n.Attempts > 0 {
		return n.Attempts
	}
	return notifyAttempts
}

func (n *Notifier) backoff(retry int) time.Duration {
	if n.Backoff != nil {
		return n.Backoff(retry)
	}
	return time.Duration(1<<uint(retry)) * time.Second
}

func (n *Notifier) bodyCap() int64 {
	if n.BodyCap > 0 {
		return n.BodyCap
	}
	return notifyBodyCap
}

// Send POSTs the summary, retrying with backoff. Errors name the failure,
// never the URL.
func (n *Notifier) Send(ctx context.Context, s Summary) error {
	s.SchemaVersion = "1"
	body, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("notify: encode: %w", err)
	}
	var attemptErr error
	for i := 0; i < n.attempts(); i++ {
		if i > 0 {
			if err := sleepCtx(ctx, n.backoff(i-1)); err != nil {
				return err
			}
		}
		attemptErr = n.post(ctx, body)
		if attemptErr == nil {
			return nil
		}
		if n.Log != nil {
			n.Log.Debug("notify attempt failed", "attempt", i+1, "error", attemptErr.Error())
		}
	}
	return fmt.Errorf("%v after %d attempts", attemptErr, n.attempts())
}

func (n *Notifier) post(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL.String(), bytes.NewReader(body))
	if err != nil {
		return errors.New("notify: build request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.HTTP.Do(req)
	if err != nil {
		return scrubURLError(err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, n.bodyCap()))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("notify: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// scrubURLError drops the URL from request errors: webhook URLs often
// carry a token in path or query, which must reach no log or audit row.
// The operation and the underlying reason (which may name the host, never
// the token) are kept.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("notify %s: %v", ue.Op, ue.Err)
	}
	return fmt.Errorf("notify: %v", err)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
