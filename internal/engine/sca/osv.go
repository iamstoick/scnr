package sca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// OSV client constants (Section 5.6).
const (
	DefaultOSVBase  = "https://api.osv.dev"
	osvBatchSize    = 1000
	osvConcurrency  = 4
	osvRetries      = 3
	osvMaxBodyBytes = 16 << 20
	// CacheTTL for vuln details.
	CacheTTL = 7 * 24 * time.Hour
)

// Cache is the vuln_cache subset of store.Store.
type Cache interface {
	VulnCacheGet(ctx context.Context, id string, maxAge time.Duration) ([]byte, bool, error)
	VulnCachePut(ctx context.Context, id string, body []byte) error
}

// OSVClient talks to api.osv.dev.
type OSVClient struct {
	Base  string
	HTTP  *http.Client
	Cache Cache
	// Sleep is overridable for tests (backoff).
	Sleep func(time.Duration)
}

// Lookup is what the sca engine needs from a vulnerability source: OSVClient
// (online) and OfflineClient (signed bundle in the store) both satisfy it.
type Lookup interface {
	QueryBatch(ctx context.Context, pkgs []Package) ([][]string, error)
	GetVulns(ctx context.Context, ids []string) (map[string]*Vuln, error)
}

// Vuln is the subset of the OSV schema we read.
type Vuln struct {
	ID         string   `json:"id"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	Aliases    []string `json:"aliases"`
	Modified   string   `json:"modified"`
	Published  string   `json:"published"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected         []vulnAffected `json:"affected"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

type vulnAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges           []vulnRange `json:"ranges"`
	Versions         []string    `json:"versions"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	EcosystemSpecific struct {
		Severity string `json:"severity"`
	} `json:"ecosystem_specific"`
}

type vulnRange struct {
	Type   string      `json:"type"`
	Events []vulnEvent `json:"events"`
}

type vulnEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type batchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch returns, for each package (by index), the vuln IDs affecting it.
func (c *OSVClient) QueryBatch(ctx context.Context, pkgs []Package) ([][]string, error) {
	out := make([][]string, len(pkgs))
	for start := 0; start < len(pkgs); start += osvBatchSize {
		end := start + osvBatchSize
		if end > len(pkgs) {
			end = len(pkgs)
		}
		queries := make([]batchQuery, 0, end-start)
		for _, p := range pkgs[start:end] {
			var q batchQuery
			q.Package.Name, q.Package.Ecosystem, q.Version = p.QueryName(), p.Ecosystem, p.Version
			queries = append(queries, q)
		}
		body, _ := json.Marshal(map[string]any{"queries": queries})
		var resp batchResponse
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv querybatch: got %d results for %d queries", len(resp.Results), end-start)
		}
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				if v.ID != "" {
					out[start+i] = append(out[start+i], v.ID)
				}
			}
		}
	}
	return out, nil
}

// GetVulns fetches details for ids with bounded concurrency, using the cache.
func (c *OSVClient) GetVulns(ctx context.Context, ids []string) (map[string]*Vuln, error) {
	out := make(map[string]*Vuln, len(ids))
	results := make([]*Vuln, len(ids))
	sem := semaphore.NewWeighted(osvConcurrency)
	g, gctx := errgroup.WithContext(ctx)
	for i, id := range ids {
		if err := sem.Acquire(gctx, 1); err != nil {
			return nil, err
		}
		g.Go(func() error {
			defer sem.Release(1)
			v, err := c.GetVuln(gctx, id)
			if err != nil {
				return err
			}
			results[i] = v
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for _, v := range results {
		if v != nil {
			out[v.ID] = v
		}
	}
	return out, nil
}

// GetVuln fetches one vuln, from cache when fresh.
func (c *OSVClient) GetVuln(ctx context.Context, id string) (*Vuln, error) {
	if !validVulnID(id) {
		return nil, fmt.Errorf("osv: bad vuln id %q", id)
	}
	if c.Cache != nil {
		if b, ok, err := c.Cache.VulnCacheGet(ctx, id, CacheTTL); err == nil && ok {
			var v Vuln
			if json.Unmarshal(b, &v) == nil && v.ID != "" {
				return &v, nil
			}
		}
	}
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+id, nil, &raw); err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	if v.ID == "" {
		v.ID = id
	}
	if c.Cache != nil {
		_ = c.Cache.VulnCachePut(ctx, id, raw)
	}
	return &v, nil
}

func validVulnID(id string) bool {
	if len(id) < 4 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

var errNoHTTPClient = errors.New("osv: no HTTP client")

func (c *OSVClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	base := c.Base
	if base == "" {
		base = DefaultOSVBase
	}
	if c.HTTP == nil {
		// Never fall back to http.DefaultClient: the caller passes an
		// endpoint client restricted to the OSV host (SAFETY.md item 9).
		return errNoHTTPClient
	}
	client := c.HTTP
	sleep := c.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	var lastErr error
	for attempt := 0; attempt <= osvRetries; attempt++ {
		if attempt > 0 {
			d := time.Duration(1<<uint(attempt-1))*time.Second + time.Duration(rand.Intn(500))*time.Millisecond //nolint:gosec // jitter only
			sleep(d)
		}
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, rdr)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "scnr")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, osvMaxBodyBytes))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("osv %s: decode: %w", path, err)
			}
			return nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("osv %s: HTTP %d", path, resp.StatusCode)
			continue
		default:
			return fmt.Errorf("osv %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data[:min(len(data), 200)])))
		}
	}
	return fmt.Errorf("osv: giving up after %d retries: %w", osvRetries, lastErr)
}
