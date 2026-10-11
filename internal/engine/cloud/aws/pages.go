package aws

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Pagination caps per inventory list (spec 3.3).
const (
	maxPages = 100
	maxItems = 10000
)

// truncation records one inventory list that hit a cap.
type truncation struct {
	list   string
	region string
	pages  int
	items  int
}

// coverage collects what the run could not cover: truncated lists,
// checks that errored, and whether the call budget ran out. It is shared
// by the regional goroutines.
type coverage struct {
	mu        sync.Mutex
	truncated []truncation
	failed    []string
	budget    bool
}

func (c *coverage) truncate(t truncation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.truncated = append(c.truncated, t)
}

func (c *coverage) fail(check, region string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	where := check
	if region != "" {
		where += "@" + region
	}
	c.failed = append(c.failed, fmt.Sprintf("%s: %v", where, err))
}

// reason summarises the gaps for engine.PartialError; "" when complete.
func (c *coverage) reason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	if c.budget {
		parts = append(parts, "API call budget exhausted")
	}
	if n := len(c.truncated); n > 0 {
		parts = append(parts, fmt.Sprintf("%d inventory list(s) truncated", n))
	}
	if n := len(c.failed); n > 0 {
		sort.Strings(c.failed)
		parts = append(parts, fmt.Sprintf("%d check(s) failed (%s)", n, c.failed[0]))
	}
	if len(parts) == 0 {
		return ""
	}
	s := parts[0]
	for _, p := range parts[1:] {
		s += "; " + p
	}
	return s
}

// pages drives a paginator through hasMore/next until it ends or a cap is
// hit. next returns the number of items in the page it consumed. On a cap
// the truncation is recorded in cov and iteration stops; the items already
// seen have been handled by next, so findings for them stand.
func pages(ctx context.Context, cov *coverage, list, region string, hasMore func() bool, next func(context.Context) (int, error)) error {
	np, items := 0, 0
	for hasMore() {
		if np >= maxPages || items >= maxItems {
			cov.truncate(truncation{list: list, region: region, pages: np, items: items})
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := next(ctx)
		if err != nil {
			return err
		}
		np++
		items += n
	}
	return nil
}
