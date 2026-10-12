package plugin

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/iamstoick/scnr/internal/safety"
)

// brokerFixture starts an httptest server and a broker pinned to it.
type brokerFixture struct {
	server *httptest.Server
	broker *Broker
	ua     atomic.Value // last User-Agent seen
}

func newBrokerFixture(t *testing.T, max int) *brokerFixture {
	t.Helper()
	fx := &brokerFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		fx.ua.Store(r.Header.Get("User-Agent"))
		w.Header().Set("X-Test", "yes")
		w.Header().Set("Set-Cookie", "session=secret")
		_, _ = w.Write([]byte("hello"))
	})
	mux.HandleFunc("/redir", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/x", http.StatusFound)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, maxBrokerBody+1))
	})
	fx.server = httptest.NewServer(mux)
	t.Cleanup(fx.server.Close)
	scope, err := safety.NewScope([]string{"127.0.0.1"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewBroker(BrokerConfig{Name: "tplug", Origin: fx.server.URL, Max: max}, &safety.Dialer{Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Stop)
	fx.broker = b
	return fx
}

func (fx *brokerFixture) roundTrip(t *testing.T, req string) brokerResponse {
	t.Helper()
	c, err := net.Dial("unix", fx.broker.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Fail fast instead of hanging to the go test timeout if the
	// broker ever stops answering.
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintln(c, req); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var resp brokerResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("bad broker response %q: %v", line, err)
	}
	return resp
}

// E5: the broker fetches same-origin GET/HEAD through the scan's
// scope-checked client and nothing else.
func TestBroker(t *testing.T) {
	t.Run("get-ok", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/ok"}`)
		if resp.Error != "" || resp.Status != 200 {
			t.Fatalf("resp = %+v", resp)
		}
		body, _ := base64.StdEncoding.DecodeString(resp.Body)
		if string(body) != "hello" {
			t.Fatalf("body = %q", body)
		}
		if resp.Headers["X-Test"] != "yes" {
			t.Fatalf("headers = %v", resp.Headers)
		}
		// Cookies never cross into plugin land.
		for k := range resp.Headers {
			if strings.EqualFold(k, "Set-Cookie") {
				t.Fatalf("Set-Cookie leaked: %v", resp.Headers)
			}
		}
		ua, _ := fx.ua.Load().(string)
		if !strings.HasPrefix(ua, "scnr-plugin/tplug") {
			t.Fatalf("user-agent = %q", ua)
		}
	})

	t.Run("head-ok", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"HEAD","url":"`+fx.server.URL+`/ok"}`)
		if resp.Error != "" || resp.Status != 200 {
			t.Fatalf("resp = %+v", resp)
		}
	})

	t.Run("user-agent-suffix", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/ok","headers":{"User-Agent":"mycheck/2"}}`)
		if resp.Error != "" {
			t.Fatalf("resp = %+v", resp)
		}
		ua, _ := fx.ua.Load().(string)
		if ua != "scnr-plugin/tplug mycheck/2" {
			t.Fatalf("user-agent = %q", ua)
		}
	})

	t.Run("method-restricted", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		for _, m := range []string{"POST", "PUT", "DELETE", ""} {
			resp := fx.roundTrip(t, `{"id":"1","method":"`+m+`","url":"`+fx.server.URL+`/ok"}`)
			if resp.Error != "E_BAD_REQUEST" {
				t.Fatalf("method %q: resp = %+v", m, resp)
			}
		}
	})

	t.Run("forbidden-headers", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		for _, h := range []string{"Authorization", "Cookie", "Host", "X-Custom-Thing"} {
			resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/ok","headers":{"`+h+`":"x"}}`)
			if resp.Error != "E_FORBIDDEN_HEADER" {
				t.Fatalf("header %q: resp = %+v", h, resp)
			}
		}
	})

	t.Run("same-origin", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		for _, u := range []string{
			"http://example.com/",
			"http://127.0.0.1:1/elsewhere",
			"ftp://127.0.0.1/x",
			"https://" + strings.TrimPrefix(fx.server.URL, "http://") + "/ok", // scheme downgrade mismatch
		} {
			resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+u+`"}`)
			if resp.Error != "E_SCOPE_NOT_ALLOWED" && resp.Error != "E_BAD_REQUEST" {
				t.Fatalf("url %q: resp = %+v", u, resp)
			}
			if u == "http://example.com/" && resp.Error != "E_SCOPE_NOT_ALLOWED" {
				t.Fatalf("off-origin gave %q, want E_SCOPE_NOT_ALLOWED", resp.Error)
			}
		}
	})

	t.Run("unknown-field", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/ok","follow":true}`)
		if resp.Error != "E_BAD_REQUEST" {
			t.Fatalf("resp = %+v", resp)
		}
	})

	t.Run("bad-json", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `not json`)
		if resp.Error != "E_BAD_REQUEST" {
			t.Fatalf("resp = %+v", resp)
		}
	})

	t.Run("redirect-out-of-scope", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/redir"}`)
		if resp.Error != "E_FETCH_FAILED" {
			t.Fatalf("resp = %+v", resp)
		}
	})

	t.Run("oversize-body", func(t *testing.T) {
		fx := newBrokerFixture(t, 0)
		resp := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/big"}`)
		if resp.Error != "E_BODY_TOO_LARGE" {
			t.Fatalf("resp = %+v", resp)
		}
	})

	t.Run("budget", func(t *testing.T) {
		fx := newBrokerFixture(t, 1)
		first := fx.roundTrip(t, `{"id":"1","method":"GET","url":"`+fx.server.URL+`/ok"}`)
		if first.Error != "" {
			t.Fatalf("first = %+v", first)
		}
		second := fx.roundTrip(t, `{"id":"2","method":"GET","url":"`+fx.server.URL+`/ok"}`)
		if second.Error != "E_BUDGET_EXCEEDED" {
			t.Fatalf("second = %+v", second)
		}
	})

	t.Run("no-dialer", func(t *testing.T) {
		if _, err := NewBroker(BrokerConfig{Name: "x", Origin: "https://example.com"}, nil); err == nil {
			t.Fatal("broker started without a dialer")
		}
	})

	t.Run("bad-origin", func(t *testing.T) {
		scope, _ := safety.NewScope([]string{"127.0.0.1"}, nil, nil)
		if _, err := NewBroker(BrokerConfig{Name: "x", Origin: "://bad"}, &safety.Dialer{Scope: scope}); err == nil {
			t.Fatal("broker started with a bad origin")
		}
	})
}

// sameOrigin is unit-tested without a network: URL targets pin the
// scheme (no https->http downgrade); host targets pin host+port only.
func TestSameOrigin(t *testing.T) {
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	origin := mustParse("https://example.com:8443/app")
	cases := []struct {
		url       string
		anyScheme bool
		want      bool
	}{
		{"https://example.com:8443/other", false, true},
		{"https://example.com:8443/other", true, true},
		{"http://example.com:8443/other", false, false}, // downgrade
		{"http://example.com:8443/other", true, true},   // host target: ok
		{"https://example.com/other", false, false},     // port differs
		{"https://example.com/other", true, false},
		{"https://evil.com:8443/other", false, false},
		{"https://evil.com:8443/other", true, false},
		{"https://EXAMPLE.com:8443/other", false, true}, // case-insensitive host
	}
	for _, c := range cases {
		if got := sameOrigin(mustParse(c.url), origin, c.anyScheme); got != c.want {
			t.Errorf("sameOrigin(%s, anyScheme=%v) = %v, want %v", c.url, c.anyScheme, got, c.want)
		}
	}
}

// Every broker reply is flushed immediately, including error replies
// to malformed lines: the handler loops back for the next request, so
// a buffered-but-unflushed reply would deadlock the client. Runs over
// an in-memory pipe, so no sockets are needed.
func TestBrokerFlushesErrorReplies(t *testing.T) {
	b := &Broker{}
	server, client := net.Pipe()
	defer client.Close()
	go b.handle(server)
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	for _, line := range []string{"not json", `{"bogus":true}`} {
		if _, err := fmt.Fprintln(client, line); err != nil {
			t.Fatal(err)
		}
		raw, err := bufio.NewReader(client).ReadBytes('\n')
		if err != nil {
			t.Fatalf("no reply to %q: %v", line, err)
		}
		var resp brokerResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.Error != "E_BAD_REQUEST" {
			t.Fatalf("resp = %+v", resp)
		}
	}
}

// The socket directory is private and removed on Stop.
func TestBrokerSocketHygiene(t *testing.T) {
	fx := newBrokerFixture(t, 0)
	addr := fx.broker.Addr()
	if !strings.HasSuffix(addr, ".sock") && !strings.Contains(addr, "broker.sock") {
		t.Fatalf("addr = %q", addr)
	}
	fx.broker.Stop()
	if _, err := net.Dial("unix", addr); err == nil {
		t.Fatal("socket accepts after Stop")
	}
}
