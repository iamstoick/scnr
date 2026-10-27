// Package azure is the native Azure posture engine: read-only ARM checks
// against one subscription (storage, key vault, network, SQL). It never
// writes, never assigns roles, and never touches credentials beyond the
// service-principal or managed-identity login the user configured.
package azure

import (
	"context"
	"embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
)

//go:embed rules/*.yaml
var assets embed.FS

// Name of the engine.
const Name = "cloud-azure"

// Scheme prefix of the target value.
const Scheme = "azure://"

// Run-shape constants.
const (
	checkTimeout = 2 * time.Minute
	userAgent    = "scnr-cloud-azure"
	budgetStd    = 200
	budgetDeep   = 500
)

// Subscription ID shape (RFC 4122 UUID, any case).
var subscriptionRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Engine implements engine.Engine for azure:// targets.
type Engine struct {
	rules engine.RuleSet
	// Config is cloud.azure from the scope file.
	Config config.CloudAzure
	// testCred replaces the credential chain (tests only); the CLI never
	// sets it.
	testCred   azcore.TokenCredential
	testSource string
	// Test hooks: a base endpoint for every ARM call and the endpoint
	// hosts to allow instead of management.azure.com (which also allows
	// loopback). The CLI never sets either.
	BaseEndpoint  string
	EndpointHosts []string
	// HTTPTimeout for one API request; zero means 60s.
	HTTPTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*session // by credential hash; filled by Identity, reused by Run
}

// New loads the rules.
func New(cfg config.CloudAzure) (*Engine, error) {
	rs, err := engine.LoadRules(assets, "rules", Name)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rs, Config: cfg, sessions: map[string]*session{}}, nil
}

// Name implements engine.Engine.
func (e *Engine) Name() string { return Name }

// Rules exposes the rule prose.
func (e *Engine) Rules() engine.RuleSet { return e.rules }

// Supports azure:// cloud targets.
func (e *Engine) Supports(t domain.Target) bool {
	return t.Type == domain.TargetCloud && strings.HasPrefix(t.Value, Scheme)
}

// Plan implements engine.Engine.
func (e *Engine) Plan(_ context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	sub := subscriptionOf(t)
	if sub == "" {
		sub = "the configured subscription"
	}
	budget := int64(budgetStd)
	if o.Profile.Name == "deep" {
		budget = budgetDeep
	}
	return engine.Plan{
		Summary:     fmt.Sprintf("%d read-only Azure posture checks (Storage, Key Vault, Network, SQL) on subscription %s; at most %d API calls", len(checks), sub, budget),
		EstRequests: 100, EstDuration: 3 * time.Minute, Network: true,
	}, nil
}

// subscriptionOf extracts the subscription from azure://<id> (empty for
// azure:// and for the post-gate azure://<id> form, where the profile has
// moved to Labels["profile"]).
func subscriptionOf(t domain.Target) string {
	if p := t.Labels["profile"]; p != "" {
		return p
	}
	rest := strings.TrimPrefix(t.Value, Scheme)
	if subscriptionRe.MatchString(rest) {
		return ""
	}
	return rest
}

// accountOf returns the confirmed subscription from azure://<id>, or "".
func accountOf(t domain.Target) string {
	rest := strings.TrimPrefix(t.Value, Scheme)
	if subscriptionRe.MatchString(rest) {
		return rest
	}
	return ""
}

func budgetFor(p engine.Profile) int64 {
	if p.Name == "deep" {
		return budgetDeep
	}
	return budgetStd
}
