package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/iamstoick/scnr/internal/safety"
)

// armHosts are the only hosts an ARM call may go to: the public cloud
// Resource Manager and the Entra token endpoint the SDK uses. Test
// overrides replace the base, never extend this list silently.
var armHosts = []string{"management.azure.com", "login.microsoftonline.com"}

// BudgetExceededError stops the run when the API budget is gone; coverage
// is then reported partial, never silently short.
type BudgetExceededError struct{ Budget int64 }

func (e *BudgetExceededError) Error() string {
	return fmt.Sprintf("azure api budget of %d calls exhausted", e.Budget)
}

// budget counts API calls down to zero.
type budget struct {
	mu   sync.Mutex
	left int64
}

func newBudget(total int64) *budget { return &budget{left: total} }

func (b *budget) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.left <= 0 {
		return false
	}
	b.left--
	return true
}

// apiError is a decoded ARM error envelope.
type apiError struct {
	Status int
	Code   string
	Msg    string
}

func (e *apiError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("arm: HTTP %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("arm: HTTP %d", e.Status)
}

// session holds one login: the credential, its source and a call budget.
type session struct {
	cred   tokenSource
	source string
	budget *budget
	client *http.Client
	base   string
}

func (s *session) token(ctx context.Context) (string, error) {
	return s.cred.Token(ctx)
}

// armGet performs one authorised GET and decodes the JSON body into out.
// 404 means "absent", never failure; anything else non-2xx is an error
// naming only the status and the ARM error code.
func (s *session) armGet(ctx context.Context, path string, out any) error {
	if !s.budget.take() {
		return &BudgetExceededError{Budget: -1}
	}
	tok, err := s.token(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return &apiError{Status: 404}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &apiError{Status: resp.StatusCode}
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &env) == nil {
			ae.Code = env.Error.Code
		}
		if ae.Code == "SubscriptionNotFound" {
			ae.Status = 404
			return ae
		}
		return ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("arm: bad JSON from %s", path)
	}
	return nil
}

// armList follows value/nextLink pages, calling emit for each page of
// values. Only GETs are ever issued.
func armList[T any](ctx context.Context, s *session, first string, emit func([]T) error) error {
	next := first
	for next != "" {
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := s.armGet(ctx, next, &page); err != nil {
			return err
		}
		if err := emit(page.Value); err != nil {
			return err
		}
		next = ""
		if page.NextLink != "" {
			u, err := url.Parse(page.NextLink)
			if err != nil {
				return fmt.Errorf("arm: bad nextLink")
			}
			next = u.RequestURI()
			if next == "" || next[0] != '/' {
				return fmt.Errorf("arm: absolute nextLink refused")
			}
		}
	}
	return nil
}

// isNotFound reports the "absent" errors callers skip over.
func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == 404
}

// newHTTPClient builds the ARM transport: timeouts, a user agent, and a
// hard host allowlist. Test BaseEndpoints add their host via EndpointHosts.
func newHTTPClient(hosts []string, timeout time.Duration) *http.Client {
	allowed := append([]string{}, armHosts...)
	allowed = append(allowed, hosts...)
	return safety.NewAllowlistedClient(allowed, timeout, userAgent)
}
