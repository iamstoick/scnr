package aws

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go/middleware"
	"golang.org/x/time/rate"

	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/safety"
)

// Transport and retry constants (spec 3.3).
const (
	maxResponseBytes = 16 << 20
	maxAttempts      = 5
	maxBackoff       = 20 * time.Second
	// globalRegion hosts the global services (IAM, STS, S3 listing,
	// CloudTrail trail inventory) and the region discovery call.
	globalRegion = "us-east-1"
)

// Call budgets and per-region request rates by profile.
const (
	budgetStandard = 5000
	budgetDeep     = 20000
	rateStandard   = 10
	rateDeep       = 20
)

// endpointHosts is the allowlist for API traffic: every AWS API endpoint
// is a subdomain of amazonaws.com (China and GovCloud partitions are not
// supported in this version).
var endpointHosts = []string{"*.amazonaws.com"}

// session is the per-run bundle every client is built from: one resolved
// credential object, one HTTP client, one budget, one limiter per region.
// The gate caches it through Identity (empty profile); Run installs the
// run's profile with setProfile before any check runs.
type session struct {
	creds    aws.CredentialsProvider
	identity safety.CloudIdentity
	http     aws.HTTPClient
	budget   *budget
	rate     int
	profName string  // profile the budget and rate were built for
	base     *string // BaseEndpoint override (tests only)

	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// setProfile installs the run's profile on a cached session: the budget
// total moves by the delta so calls already spent (identity, assume-role)
// still count, and the per-region limiters are rebuilt at the new rate.
// A session already on this profile is untouched, so a test-installed
// budget survives. Call before any check runs; Run is the only caller.
func (s *session) setProfile(p engine.Profile) {
	if s.profName == p.Name {
		return
	}
	if want := budgetFor(p); want != s.budget.total {
		s.budget.remaining.Add(want - s.budget.total)
		s.budget.total = want
	}
	s.mu.Lock()
	s.rate = rateFor(p)
	s.limiters = map[string]*rate.Limiter{}
	s.profName = p.Name
	s.mu.Unlock()
}

func (s *session) limiter(region string) *rate.Limiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limiters == nil {
		s.limiters = map[string]*rate.Limiter{}
	}
	l, ok := s.limiters[region]
	if !ok {
		l = rate.NewLimiter(rate.Limit(s.rate), s.rate)
		s.limiters[region] = l
	}
	return l
}

// config is the single place an aws.Config is assembled. guard is the
// Initialize-step operation allowlist (ReadOnlyGuard for posture clients,
// credentialGuard for the credential chain's STS client); the Meter is
// inserted after the retryer so retries are rate-limited and budgeted too.
func (s *session) config(region string, creds aws.CredentialsProvider, guard middleware.InitializeMiddleware) aws.Config {
	meter := Meter{limiter: s.limiter(region), budget: s.budget}
	return aws.Config{
		Region:       region,
		Credentials:  creds,
		HTTPClient:   s.http,
		BaseEndpoint: s.base,
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(o *retry.StandardOptions) {
				o.MaxAttempts = maxAttempts
				o.MaxBackoff = maxBackoff
				o.RateLimiter = ratelimit.None // the Meter does the limiting
			})
		},
		APIOptions: []func(*middleware.Stack) error{
			func(stack *middleware.Stack) error {
				if err := stack.Initialize.Add(guard, middleware.Before); err != nil {
					return err
				}
				return stack.Finalize.Insert(meter, "Retry", middleware.After)
			},
		},
	}
}

// clients are the posture clients for one region.
type clients struct {
	region string
	iam    *iam.Client
	s3     *s3.Client
	ec2    *ec2.Client
	rds    *rds.Client
	ct     *cloudtrail.Client
	kms    *kms.Client
}

// clients builds the read-only posture clients for region from the
// session's resolved credentials.
func (s *session) clients(region string) *clients {
	cfg := s.config(region, s.creds, ReadOnlyGuard{})
	return &clients{
		region: region,
		iam:    iam.NewFromConfig(cfg),
		s3: s3.NewFromConfig(cfg, func(o *s3.Options) {
			// A test endpoint is one host for every bucket, so path style
			// is the only addressing that can reach it.
			o.UsePathStyle = s.base != nil
		}),
		ec2: ec2.NewFromConfig(cfg),
		rds: rds.NewFromConfig(cfg),
		ct:  cloudtrail.NewFromConfig(cfg),
		kms: kms.NewFromConfig(cfg),
	}
}

// stsClient builds the STS client used for identity confirmation and by
// the credential chain (AssumeRole*). It is the only client not behind
// ReadOnlyGuard; credentialGuard allows exactly three operations.
func (s *session) stsClient(creds aws.CredentialsProvider) *sts.Client {
	return sts.NewFromConfig(s.config(globalRegion, creds, credentialGuard{}))
}

// callerIdentity runs sts:GetCallerIdentity and returns the account and
// principal ARN.
func (s *session) callerIdentity(ctx context.Context) (account, arn string, err error) {
	out, err := s.stsClient(s.creds).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", err
	}
	return aws.ToString(out.Account), aws.ToString(out.Arn), nil
}

// bodyLimitTransport caps every response body the SDK reads at
// maxResponseBytes; the endpoint client beneath it already caps headers
// and refuses non-allowlisted hosts.
type bodyLimitTransport struct{ rt http.RoundTripper }

func (t *bodyLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &limitedBody{Reader: io.LimitReader(resp.Body, maxResponseBytes), c: resp.Body}
	return resp, nil
}

type limitedBody struct {
	io.Reader
	c io.Closer
}

func (l *limitedBody) Close() error { return l.c.Close() }

// newHTTPClient returns the endpoint-allowlisted client for API traffic.
// hosts defaults to the public AWS endpoints with private address space
// refused; tests pass their httptest host and allow loopback.
func newHTTPClient(hosts []string, timeout time.Duration, ua string) (*http.Client, error) {
	policy := safety.EndpointPolicy{RefusePrivate: true}
	if len(hosts) == 0 {
		hosts = endpointHosts
	} else {
		policy.RefusePrivate = false
	}
	c, err := safety.NewEndpointClientPolicy(hosts, safety.HTTPOptions{Timeout: timeout, UserAgent: ua}, policy)
	if err != nil {
		return nil, err
	}
	c.Transport = &bodyLimitTransport{rt: c.Transport}
	return c, nil
}
