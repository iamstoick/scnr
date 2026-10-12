package safety

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
)

// TestIntrusiveGateTable (D3): intrusive checks run only with the flag,
// an intrusive_allow match, and a private target or ownership proof.
// Interactive consent alone never suffices for public targets.
func TestIntrusiveGateTable(t *testing.T) {
	priv := netip.MustParseAddr("192.168.1.10")
	pub := netip.MustParseAddr("203.0.113.5")
	urlTarget := func(raw, host string) domain.Target {
		return domain.Target{Raw: raw, Type: domain.TargetURL, Value: raw, Hostname: host}
	}
	verified := func(context.Context, string) (bool, error) { return true, nil }
	unverified := func(context.Context, string) (bool, error) { return false, nil }
	verr := func(context.Context, string) (bool, error) { return false, errors.New("db down") }

	cases := []struct {
		name      string
		dec       *Decision
		allowFlag bool
		scope     []string // intrusive_allow
		deny      []string
		verified  VerifiedFunc
		wantOK    bool
		wantHint  string // substring of the refusal reason ("" when allowed)
		wantErr   bool
	}{
		{"no flag", &Decision{Target: urlTarget("http://192.168.1.10/", "192.168.1.10"), Addrs: []netip.Addr{priv}}, false, []string{"192.168.1.10"}, nil, nil, false, "--allow-intrusive", false},
		{"non-URL target", &Decision{Target: domain.Target{Raw: "192.168.1.10", Type: domain.TargetHost, Value: "192.168.1.10", Hostname: "192.168.1.10"}, Addrs: []netip.Addr{priv}}, true, []string{"192.168.1.10"}, nil, nil, false, "URL targets only", false},
		{"not in intrusive_allow", &Decision{Target: urlTarget("http://192.168.1.10/", "192.168.1.10"), Addrs: []netip.Addr{priv}}, true, []string{"10.0.0.0/8"}, nil, nil, false, "intrusive_allow", false},
		{"empty intrusive_allow", &Decision{Target: urlTarget("http://192.168.1.10/", "192.168.1.10"), Addrs: []netip.Addr{priv}}, true, nil, nil, nil, false, "intrusive_allow", false},
		{"deny wins", &Decision{Target: urlTarget("http://192.168.1.10/", "192.168.1.10"), Addrs: []netip.Addr{priv}}, true, []string{"192.168.0.0/16"}, []string{"192.168.1.10"}, nil, false, "deny entry", false},
		{"private allowed", &Decision{Target: urlTarget("http://192.168.1.10/", "192.168.1.10"), Addrs: []netip.Addr{priv}}, true, []string{"192.168.0.0/16"}, nil, nil, true, "", false},
		{"public verified allowed", &Decision{Target: urlTarget("https://app.example/", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"app.example"}, nil, verified, true, "", false},
		{"public unverified refused", &Decision{Target: urlTarget("https://app.example/", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"app.example"}, nil, unverified, false, "scnr verify app.example", false},
		{"public no verifier refused", &Decision{Target: urlTarget("https://app.example/", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"app.example"}, nil, nil, false, "ownership verification", false},
		{"verification error", &Decision{Target: urlTarget("https://app.example/", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"app.example"}, nil, verr, false, "", true},
		{"url prefix bounds intrusive", &Decision{Target: urlTarget("https://app.example/admin", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"https://app.example/app"}, nil, verified, false, "intrusive_allow", false},
		{"url prefix match", &Decision{Target: urlTarget("https://app.example/app/x", "app.example"), Public: true, Addrs: []netip.Addr{pub}}, true, []string{"https://app.example/app"}, nil, verified, true, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewScope(nil, c.deny, c.scope)
			if err != nil {
				t.Fatal(err)
			}
			g := &IntrusiveGate{Scope: s, Verified: c.verified}
			ok, reason, err := g.Decide(context.Background(), c.dec, c.allowFlag)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if ok != c.wantOK {
				t.Fatalf("ok=%v reason=%q", ok, reason)
			}
			if !ok && !strings.Contains(reason, c.wantHint) {
				t.Fatalf("reason %q lacks %q", reason, c.wantHint)
			}
		})
	}
	if _, _, err := (&IntrusiveGate{}).Decide(context.Background(), nil, true); err == nil {
		t.Fatal("nil decision accepted")
	}
}
