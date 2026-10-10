// Package vulndb downloads and parses the CISA KEV catalogue and FIRST EPSS
// scores into the store (Phase 1), and enriches findings from them.
package vulndb

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/store"
)

// Upstream URLs (the only non-target hosts scnr ever contacts besides osv.dev).
const (
	KEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	EPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

	// MaxFeedBytes caps a downloaded feed.
	MaxFeedBytes = 256 << 20
	// StaleAfter is when doctor warns the DB is old.
	StaleAfter = 7 * 24 * time.Hour
)

// Updater fetches feeds. URLs are overridable for tests.
type Updater struct {
	Store   *store.Store
	HTTP    *http.Client
	KEVURL  string
	EPSSURL string
}

// UpdateAll loads KEV then EPSS.
func (u *Updater) UpdateAll(ctx context.Context) (kev, epss int, err error) {
	if kev, err = u.UpdateKEV(ctx); err != nil {
		return
	}
	epss, err = u.UpdateEPSS(ctx)
	return
}

// UpdateKEV downloads and stores the KEV catalogue.
func (u *Updater) UpdateKEV(ctx context.Context) (int, error) {
	url := u.KEVURL
	if url == "" {
		url = KEVURL
	}
	rc, err := u.fetch(ctx, url)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	entries, version, err := ParseKEV(rc)
	if err != nil {
		return 0, fmt.Errorf("parse KEV: %w", err)
	}
	if err := u.Store.ReplaceKEV(ctx, entries, version); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// UpdateEPSS downloads and stores EPSS scores.
func (u *Updater) UpdateEPSS(ctx context.Context) (int, error) {
	url := u.EPSSURL
	if url == "" {
		url = EPSSURL
	}
	rc, err := u.fetch(ctx, url)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	var r io.Reader = rc
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(rc)
		if err != nil {
			return 0, fmt.Errorf("gunzip EPSS: %w", err)
		}
		defer gz.Close()
		r = gz
	}
	entries, version, err := ParseEPSS(r)
	if err != nil {
		return 0, fmt.Errorf("parse EPSS: %w", err)
	}
	if err := u.Store.ReplaceEPSS(ctx, entries, version); err != nil {
		return 0, err
	}
	return len(entries), nil
}

func (u *Updater) fetch(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "scnr")
	c := u.HTTP
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	return struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, MaxFeedBytes), resp.Body}, nil
}

type kevFeed struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID      string `json:"cveID"`
		DateAdded  string `json:"dateAdded"`
		DueDate    string `json:"dueDate"`
		VendorProj string `json:"vendorProject"`
		Product    string `json:"product"`
	} `json:"vulnerabilities"`
}

// ParseKEV decodes the KEV JSON feed (only known fields are copied).
func ParseKEV(r io.Reader) ([]store.KEVEntry, string, error) {
	var feed kevFeed
	if err := json.NewDecoder(r).Decode(&feed); err != nil {
		return nil, "", err
	}
	out := make([]store.KEVEntry, 0, len(feed.Vulnerabilities))
	for _, v := range feed.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !strings.HasPrefix(cve, "CVE-") {
			continue
		}
		out = append(out, store.KEVEntry{CVE: cve, Added: v.DateAdded, Due: v.DueDate, Product: strings.TrimSpace(v.VendorProj + " " + v.Product)})
	}
	return out, feed.CatalogVersion, nil
}

// ParseEPSS decodes the EPSS CSV (a "#model_version..." comment line, then
// header cve,epss,percentile).
func ParseEPSS(r io.Reader) ([]store.EPSSEntry, string, error) {
	cr := csv.NewReader(r)
	cr.Comment = 0
	cr.FieldsPerRecord = -1
	var out []store.EPSSEntry
	version := ""
	headerSeen := false
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if len(rec) == 0 {
			continue
		}
		if strings.HasPrefix(rec[0], "#") {
			version = strings.TrimPrefix(strings.Join(rec, ","), "#")
			continue
		}
		if !headerSeen {
			headerSeen = true
			if strings.EqualFold(rec[0], "cve") {
				continue
			}
		}
		if len(rec) < 3 {
			continue
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, store.EPSSEntry{CVE: strings.ToUpper(rec[0]), Score: score, Percentile: pct})
	}
	return out, version, nil
}

// Enricher annotates findings with KEV/EPSS from the store.
type Enricher struct {
	Store *store.Store
	// Available is false when both tables are empty; callers note
	// "exploit data unavailable" in reports.
	Available bool
}

// NewEnricher checks whether exploit data exists.
func NewEnricher(ctx context.Context, s *store.Store) (*Enricher, error) {
	metas, err := s.VulnDBStatus(ctx)
	if err != nil {
		return nil, err
	}
	e := &Enricher{Store: s}
	for _, m := range metas {
		if m.Rows > 0 {
			e.Available = true
		}
	}
	return e, nil
}

// Enrich sets KEV and EPSS on a finding from its CVE list (max over CVEs).
func (e *Enricher) Enrich(ctx context.Context, f *domain.Finding) error {
	if e == nil || !e.Available || len(f.CVEs) == 0 {
		return nil
	}
	var best *float64
	for _, cve := range f.CVEs {
		kev, err := e.Store.LookupKEV(ctx, cve)
		if err != nil {
			return err
		}
		if kev {
			f.KEV = true
		}
		score, ok, err := e.Store.LookupEPSS(ctx, cve)
		if err != nil {
			return err
		}
		if ok && (best == nil || score > *best) {
			s := score
			best = &s
		}
	}
	if best != nil {
		f.EPSS = best
	}
	return nil
}
