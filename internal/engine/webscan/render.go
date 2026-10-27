package webscan

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/iamstoick/scnr/internal/safety"
)

const (
	// defaultRenderTimeout bounds one page render: navigate, hydrate,
	// serialise. Renders are a bounded fallback, not the crawl itself.
	defaultRenderTimeout = 20 * time.Second
	// renderSettle waits for client hydration after the load event.
	renderSettle = 1500 * time.Millisecond
	// defaultMaxRenders caps rendered pages per target.
	defaultMaxRenders = 10
)

// Renderer returns post-JavaScript HTML for a URL, or an error (dead
// end, refusal, missing browser). The crawler uses it only as a fallback
// when static parsing finds nothing.
type Renderer interface {
	Render(ctx context.Context, targetURL string) ([]byte, error)
}

// BrowserBinaries tried in order when looking for a renderer.
var BrowserBinaries = []string{"chromium", "google-chrome", "chromium-browser", "chrome", "headless_shell"}

// FindBrowser returns the first browser binary on PATH.
func FindBrowser() (string, bool) {
	for _, b := range BrowserBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return p, true
		}
	}
	return "", false
}

// renderAllowed decides whether the browser may navigate to host: IP
// literals always; names only when the gate pinned exactly one address.
// The browser runs its own DNS and TLS stacks outside the scope-checked
// dialer (the same residual as the nuclei adapter), so a name pinned to
// several addresses — or to none — is never rendered.
func renderAllowed(dialer *safety.Dialer, host string) bool {
	if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && addr.IsValid() {
		return true
	}
	if dialer == nil {
		return false
	}
	return len(dialer.Pinned(host)) == 1
}

// ChromeRenderer drives system Chrome headless over CDP with a throwaway
// profile: no extensions, no background networking, images off (the DOM
// is identical), downloads and file access never used. One render is one
// Navigate plus a short hydration wait; anything else is an error.
type ChromeRenderer struct {
	Binary string
	Dialer *safety.Dialer
	// Scope admits navigation URLs (urlScopeFilter); nil admits everything
	// the caller passes, so callers must still filter.
	Scope   func(string) bool
	Timeout time.Duration
	Settle  time.Duration
	Log     *slog.Logger
}

func (r *ChromeRenderer) timeout() time.Duration {
	if r.Timeout > 0 {
		return r.Timeout
	}
	return defaultRenderTimeout
}

func (r *ChromeRenderer) settle() time.Duration {
	if r.Settle > 0 {
		return r.Settle
	}
	return renderSettle
}

// Render navigates to targetURL and returns the serialised DOM.
func (r *ChromeRenderer) Render(ctx context.Context, targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, fmt.Errorf("render: invalid target URL")
	}
	if r.Scope != nil && !r.Scope(u.String()) {
		return nil, fmt.Errorf("render: outside scope")
	}
	if !renderAllowed(r.Dialer, u.Hostname()) {
		return nil, fmt.Errorf("render: no single pinned address for %q", u.Hostname())
	}
	profile, err := os.MkdirTemp("", "scnr-render-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(profile) //nolint:errcheck // best effort temp cleanup
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(r.Binary),
		chromedp.Headless,
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
		chromedp.DisableGPU,
		chromedp.UserDataDir(profile),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
	)
	if os.Geteuid() == 0 {
		opts = append(opts, chromedp.NoSandbox) // containers run as root; profile is still throwaway
	}
	actx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	rctx, cancelTO := context.WithTimeout(actx, r.timeout())
	defer cancelTO()
	tctx, cancelBrowser := chromedp.NewContext(rctx)
	defer cancelBrowser()
	var html string
	tasks := chromedp.Tasks{
		chromedp.Navigate(u.String()),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(r.settle()),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	}
	if err := chromedp.Run(tctx, tasks); err != nil {
		return nil, fmt.Errorf("render %s: %w", targetURL, err)
	}
	if len(html) > maxBodyBytes {
		html = html[:maxBodyBytes]
	}
	return []byte(html), nil
}
