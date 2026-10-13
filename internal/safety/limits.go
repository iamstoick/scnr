package safety

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/time/rate"
)

// LimitDefaults are the Section 9 caps for one publicness class.
type LimitDefaults struct {
	RatePerSec         int
	PerHostConcurrency int
	HTTPRPSPerHost     int
	MaxHosts           int
}

// Defaults per class. Raising above 2x these requires an explicit flag.
var (
	PrivateDefaults = LimitDefaults{RatePerSec: 500, PerHostConcurrency: 64, HTTPRPSPerHost: 20, MaxHosts: 65536}
	PublicDefaults  = LimitDefaults{RatePerSec: 100, PerHostConcurrency: 16, HTTPRPSPerHost: 10, MaxHosts: 256}
)

// MaxParallelEngines is the global engine parallelism cap.
const MaxParallelEngines = 4

// Limits is the live budget shared by all engines in a scan.
type Limits struct {
	Public             bool
	RatePerSec         int
	PerHostConcurrency int
	HTTPRPSPerHost     int
	MaxHosts           int

	conn  *rate.Limiter
	mu    sync.Mutex
	hosts map[string]*rate.Limiter
}

// LimitRequest is what the user asked for (0 = default).
type LimitRequest struct {
	RatePerSec         int
	PerHostConcurrency int
	HTTPRPSPerHost     int
	MaxHosts           int
	AllowRaise         bool // --i-understand-rate-limits
}

// NewLimits builds limits for a publicness class from a request, enforcing
// the 2x ceiling unless AllowRaise is set. Returns raised=true when any value
// exceeds the default (so callers can audit it).
func NewLimits(public bool, req LimitRequest) (l *Limits, raised bool, err error) {
	d := PrivateDefaults
	if public {
		d = PublicDefaults
	}
	pick := func(name string, want, def int) (int, error) {
		if want <= 0 {
			return def, nil
		}
		if want > def {
			raised = true
		}
		if want > 2*def && !req.AllowRaise {
			return 0, &RefusalError{Code: CodeLimitTooHigh, Target: name,
				Reason: fmt.Sprintf("%d exceeds 2x default (%d); pass --i-understand-rate-limits to override", want, def)}
		}
		return want, nil
	}
	l = &Limits{Public: public, hosts: map[string]*rate.Limiter{}}
	if l.RatePerSec, err = pick("rate", req.RatePerSec, d.RatePerSec); err != nil {
		return nil, false, err
	}
	if l.PerHostConcurrency, err = pick("concurrency", req.PerHostConcurrency, d.PerHostConcurrency); err != nil {
		return nil, false, err
	}
	if l.HTTPRPSPerHost, err = pick("http_rps", req.HTTPRPSPerHost, d.HTTPRPSPerHost); err != nil {
		return nil, false, err
	}
	// MaxHosts has its own explicit override (--max-hosts) and is audited by
	// the gate, so it is not subject to the 2x rule.
	l.MaxHosts = d.MaxHosts
	if req.MaxHosts > 0 {
		l.MaxHosts = req.MaxHosts
	}
	l.conn = rate.NewLimiter(rate.Limit(l.RatePerSec), l.RatePerSec)
	return l, raised, nil
}

// WaitConn blocks until a connection attempt token is available.
func (l *Limits) WaitConn(ctx context.Context) error {
	return l.conn.Wait(ctx)
}

// WaitHTTP blocks until an HTTP request token for host is available.
func (l *Limits) WaitHTTP(ctx context.Context, host string) error {
	l.mu.Lock()
	lim, ok := l.hosts[host]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(l.HTTPRPSPerHost), l.HTTPRPSPerHost)
		l.hosts[host] = lim
	}
	l.mu.Unlock()
	return lim.Wait(ctx)
}
