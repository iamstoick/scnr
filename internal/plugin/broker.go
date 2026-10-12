package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/iamstoick/scnr/internal/safety"
)

// Broker limits (Section 5.8).
const (
	maxBrokerBody    = 1 << 20
	maxBrokerLine    = 64 << 10
	brokerReqTimeout = 30 * time.Second
)

// BrokerConfig configures the fetch broker for one plugin run.
type BrokerConfig struct {
	Name   string // plugin name, for the User-Agent
	Origin string // pinned same-origin root, e.g. https://example.com
	Max    int    // request budget for the run (0 = 500)
	// AnyScheme allows both http and https to the pinned host. Set for
	// host targets, which have no scheme to downgrade from; URL targets
	// pin the full origin including scheme.
	AnyScheme bool
}

// brokerRequest is one newline-delimited JSON request from the plugin.
type brokerRequest struct {
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// brokerResponse is the matching response.
type brokerResponse struct {
	ID      string            `json:"id"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"` // base64
	Error   string            `json:"error,omitempty"`
}

// Broker serves GET/HEAD fetches to plugins over a Unix socket. Every
// request is same-origin checked against the pinned origin and then
// fetched with the scan's own scope-checked HTTP client, so brokered
// traffic obeys the same DNS-pinning, redirect and private-address
// rules as a native engine. The child can neither see credentials (no
// Authorization/Cookie/Host headers cross) nor steer traffic elsewhere.
type Broker struct {
	cfg      BrokerConfig
	origin   *url.URL
	client   *http.Client
	listener net.Listener
	path     string
	mu       sync.Mutex
	used     int
	max      int
	stopOnce sync.Once
}

// allowedReqHeaders is the only header set a plugin may send. The
// User-Agent value is a suffix appended to scnr's own, never a full
// replacement, so brokered traffic stays identifiable.
var allowedReqHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Language": true,
	"User-Agent":      true,
}

// forbiddenReqHeaders is rejected explicitly with E_FORBIDDEN_HEADER
// (rather than silently dropped) so plugin authors notice.
var forbiddenReqHeaders = []string{"Authorization", "Cookie", "Host", "X-Forwarded-For"}

// NewBroker starts the broker on a fresh Unix socket. dialer is the
// scan's scope-checked dialer: when it is nil (path/image/cloud scans)
// brokered fetch is impossible and NewBroker refuses to start.
func NewBroker(cfg BrokerConfig, dialer *safety.Dialer) (*Broker, error) {
	if dialer == nil {
		return nil, fmt.Errorf("plugin %s: broker needs a network target", cfg.Name)
	}
	origin, err := url.Parse(cfg.Origin)
	if err != nil || origin.Hostname() == "" {
		return nil, fmt.Errorf("plugin %s: bad broker origin %q", cfg.Name, cfg.Origin)
	}
	max := cfg.Max
	if max <= 0 {
		max = 500
	}
	dir, err := os.MkdirTemp("", "scnr-broker-*")
	if err != nil {
		return nil, err
	}
	sock := filepath.Join(dir, "broker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = l.Close()
		_ = os.RemoveAll(dir)
		return nil, err
	}
	b := &Broker{
		cfg:      cfg,
		origin:   origin,
		client:   safety.NewHTTPClient(dialer.WithTimeout(10*time.Second), safety.HTTPOptions{UserAgent: "scnr-plugin/" + cfg.Name}),
		listener: l,
		path:     sock,
		max:      max,
	}
	go b.serve()
	return b, nil
}

// Addr returns the Unix socket path handed to the plugin.
func (b *Broker) Addr() string { return b.path }

// Stop closes the listener and removes the socket directory.
func (b *Broker) Stop() {
	b.stopOnce.Do(func() {
		_ = b.listener.Close()
		_ = os.RemoveAll(filepath.Dir(b.path))
	})
}

func (b *Broker) serve() {
	for {
		c, err := b.listener.Accept()
		if err != nil {
			return
		}
		go b.handle(c)
	}
}

func (b *Broker) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Minute))
	br := bufio.NewReader(io.LimitReader(c, int64(maxBrokerLine)*100))
	bw := bufio.NewWriter(c)
	defer bw.Flush()
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		if len(line) > maxBrokerLine {
			writeBrokerResp(bw, brokerResponse{Error: "E_BAD_REQUEST"})
			return
		}
		var req brokerRequest
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeBrokerResp(bw, brokerResponse{Error: "E_BAD_REQUEST"})
			continue
		}
		resp := b.fetch(req)
		resp.ID = req.ID
		writeBrokerResp(bw, resp)
	}
}

func writeBrokerResp(w *bufio.Writer, resp brokerResponse) {
	raw, _ := json.Marshal(resp)
	_, _ = w.Write(raw)
	_ = w.WriteByte('\n')
	// Every response goes out immediately: the handler loops back to
	// read the next request, so a buffered-but-unflushed error reply
	// would deadlock the client.
	_ = w.Flush()
}

// fetch validates one request and performs it.
func (b *Broker) fetch(req brokerRequest) brokerResponse {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return brokerResponse{Error: "E_BAD_REQUEST"}
	}
	for _, f := range forbiddenReqHeaders {
		for k := range req.Headers {
			if strings.EqualFold(k, f) {
				return brokerResponse{Error: "E_FORBIDDEN_HEADER"}
			}
		}
	}
	headers := map[string]string{}
	for k, v := range req.Headers {
		if !allowedReqHeaders[http.CanonicalHeaderKey(k)] {
			return brokerResponse{Error: "E_FORBIDDEN_HEADER"}
		}
		headers[http.CanonicalHeaderKey(k)] = v
	}
	u, err := url.Parse(req.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return brokerResponse{Error: "E_BAD_REQUEST"}
	}
	if !sameOrigin(u, b.origin, b.cfg.AnyScheme) {
		return brokerResponse{Error: "E_SCOPE_NOT_ALLOWED"}
	}
	b.mu.Lock()
	if b.used >= b.max {
		b.mu.Unlock()
		return brokerResponse{Error: "E_BUDGET_EXCEEDED"}
	}
	b.used++
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), brokerReqTimeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, req.Method, u.String(), nil)
	if err != nil {
		return brokerResponse{Error: "E_BAD_REQUEST"}
	}
	for k, v := range headers {
		if strings.EqualFold(k, "User-Agent") {
			hreq.Header.Set(k, "scnr-plugin/"+b.cfg.Name+" "+v)
		} else {
			hreq.Header.Set(k, v)
		}
	}
	resp, err := b.client.Do(hreq)
	if err != nil {
		return brokerResponse{Error: "E_FETCH_FAILED"}
	}
	defer resp.Body.Close()
	// Cap+1 so an oversize body is detected rather than truncated.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokerBody+1))
	if err != nil {
		return brokerResponse{Error: "E_FETCH_FAILED"}
	}
	if len(body) > maxBrokerBody {
		return brokerResponse{Error: "E_BODY_TOO_LARGE"}
	}
	out := brokerResponse{Status: resp.StatusCode, Headers: map[string]string{}}
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue // cookies never cross into plugin land
		}
		if len(vs) > 0 {
			out.Headers[k] = vs[0]
		}
	}
	out.Body = base64.StdEncoding.EncodeToString(body)
	return out
}

// sameOrigin compares host and port, plus the scheme unless anyScheme
// (host targets have no scheme to pin). URL targets pin the full origin
// (unlike finding locations, which ignore scheme): a plugin must not
// downgrade an https target to http.
func sameOrigin(u, origin *url.URL, anyScheme bool) bool {
	if !anyScheme && !strings.EqualFold(u.Scheme, origin.Scheme) {
		return false
	}
	return strings.EqualFold(u.Hostname(), origin.Hostname()) &&
		u.Port() == origin.Port()
}
