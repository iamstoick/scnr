package azure

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/safety"
)

func mustProfile(t *testing.T, name string) engine.Profile {
	t.Helper()
	p, err := engine.ProfileByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const testSub = "11111111-2222-3333-4444-555555555555"

// staticToken never touches the network: the mock server accepts any
// bearer value.
type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func testEngine(t *testing.T, srv *httptest.Server) *Engine {
	t.Helper()
	e, err := New(config.CloudAzure{})
	if err != nil {
		t.Fatal(err)
	}
	e.BaseEndpoint = srv.URL
	e.EndpointHosts = []string{"127.0.0.1"}
	e.testCred, e.testSource = staticToken{}, "test"
	return e
}

func azureTarget() domain.Target {
	return domain.Target{Type: domain.TargetCloud, Value: Scheme + testSub, Hostname: testSub, Raw: Scheme + testSub}
}

// mockARM serves one vulnerable and one clean resource per check, with the
// storage list split across two pages to exercise nextLink.
func mockARM(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/subscriptions/"+testSub, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"subscriptionId":"` + testSub + `","tenantId":"tenant-1","state":"Enabled"}`))
	})
	mux.HandleFunc("/subscriptions/"+testSub+"/providers/Microsoft.Storage/storageAccounts", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			w.Write([]byte(`{"value":[
				{"id":"/sa/tls10","name":"tls10","properties":{"publicNetworkAccess":"Disabled","allowBlobPublicAccess":false,"minimumTlsVersion":"TLS1_0"}}
			]}`))
			return
		}
		w.Write([]byte(`{"value":[
			{"id":"/sa/pubblob","name":"pubblob","properties":{"publicNetworkAccess":"Disabled","allowBlobPublicAccess":true,"minimumTlsVersion":"TLS1_2"}},
			{"id":"/sa/opennet","name":"opennet","properties":{"publicNetworkAccess":"Enabled","allowBlobPublicAccess":false,"minimumTlsVersion":"TLS1_2"}},
			{"id":"/sa/clean","name":"clean","properties":{"publicNetworkAccess":"Disabled","allowBlobPublicAccess":false,"minimumTlsVersion":"TLS1_2"}}
		],"nextLink":"/subscriptions/` + testSub + `/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01&page=2"}`))
	})
	mux.HandleFunc("/subscriptions/"+testSub+"/providers/Microsoft.KeyVault/vaults", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":[
			{"id":"/kv/open","name":"open","properties":{"publicNetworkAccess":"Enabled","enablePurgeProtection":true}},
			{"id":"/kv/nopurge","name":"nopurge","properties":{"publicNetworkAccess":"Disabled","enablePurgeProtection":false}},
			{"id":"/kv/clean","name":"clean","properties":{"publicNetworkAccess":"Disabled","enablePurgeProtection":true}}
		]}`))
	})
	mux.HandleFunc("/subscriptions/"+testSub+"/providers/Microsoft.Network/networkSecurityGroups", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":[
			{"id":"/nsg/a","name":"a","properties":{"securityRules":[
				{"name":"rdp-range","properties":{"access":"Allow","direction":"Inbound","destinationPortRange":"3380-3390","sourceAddressPrefix":"0.0.0.0/0"}},
				{"name":"web","properties":{"access":"Allow","direction":"Inbound","destinationPortRange":"443","sourceAddressPrefix":"0.0.0.0/0"}}
			]}},
			{"id":"/nsg/b","name":"b","properties":{"securityRules":[
				{"name":"ssh-any","properties":{"access":"Allow","direction":"Inbound","destinationPortRanges":["22"],"sourceAddressPrefixes":["Internet"]}},
				{"name":"ssh-lan","properties":{"access":"Allow","direction":"Inbound","destinationPortRange":"22","sourceAddressPrefix":"10.0.0.0/8"}},
				{"name":"deny-all","properties":{"access":"Deny","direction":"Inbound","destinationPortRange":"*","sourceAddressPrefix":"*"}}
			]}}
		]}`))
	})
	mux.HandleFunc("/subscriptions/"+testSub+"/providers/Microsoft.Sql/servers", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"value":[
			{"id":"/sql/open","name":"open","properties":{"publicNetworkAccess":"Enabled","minimalTlsVersion":"1.2"}},
			{"id":"/sql/clean","name":"clean","properties":{"publicNetworkAccess":"Disabled","minimalTlsVersion":"1.2"}}
		]}`))
	})
	return httptest.NewServer(mux)
}

func TestAzureRulesLoad(t *testing.T) {
	e, err := New(config.CloudAzure{})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(e.Rules()); got != 9 {
		t.Fatalf("want 9 azure rules, got %d", got)
	}
	if !e.Supports(domain.Target{Type: domain.TargetCloud, Value: Scheme + testSub}) {
		t.Fatal("must support azure:// targets")
	}
	if e.Supports(domain.Target{Type: domain.TargetCloud, Value: "aws://123456789012"}) {
		t.Fatal("must not support aws:// targets")
	}
}

func TestAzureCredentialRefusals(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	e, _ := New(config.CloudAzure{})
	if _, _, err := e.credential(); err == nil {
		t.Fatal("no credentials must refuse")
	}
	t.Setenv("AZURE_CLIENT_ID", "id-only")
	if _, _, err := e.credential(); err == nil {
		t.Fatal("partial credentials must refuse")
	}
	t.Setenv("AZURE_CLIENT_SECRET", "s3cret-value")
	if _, _, err := e.credential(); err == nil || strings.Contains(err.Error(), "s3cret-value") {
		t.Fatalf("secret must never appear: %v", err)
	}
}

func TestAzureIdentityConfirmsSubscription(t *testing.T) {
	srv := mockARM(t)
	defer srv.Close()
	e := testEngine(t, srv)
	id, err := e.Identity(context.Background(), azureTarget())
	if err != nil {
		t.Fatal(err)
	}
	if id.Provider != "azure" || id.Account != testSub {
		t.Fatalf("%+v", id)
	}
	other := domain.Target{Type: domain.TargetCloud, Value: Scheme + "22222222-2222-3333-4444-555555555555", Raw: Scheme + testSub}
	if _, err := e.Identity(context.Background(), other); err == nil {
		t.Fatal("identity for another subscription must refuse")
	}
	if _, err := e.Identity(context.Background(), domain.Target{Type: domain.TargetCloud, Value: Scheme, Raw: Scheme}); err == nil {
		t.Fatal("empty subscription must refuse")
	}
}

func TestAzureChecksAgainstMockARM(t *testing.T) {
	srv := mockARM(t)
	defer srv.Close()
	e := testEngine(t, srv)
	o := engine.Options{Profile: mustProfile(t, "standard"), Redactor: safety.NewRedactor(), Log: testLog()}
	var got []domain.Finding
	err := e.Run(context.Background(), azureTarget(), o, func(f domain.Finding) error {
		got = append(got, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"cloud.azure.storage.blob-public":          "/sa/pubblob",
		"cloud.azure.storage.public-network":       "/sa/opennet",
		"cloud.azure.storage.min-tls":              "/sa/tls10",
		"cloud.azure.keyvault.public-network":      "/kv/open",
		"cloud.azure.keyvault.no-purge-protection": "/kv/nopurge",
		"cloud.azure.nsg.open-rdp":                 "rdp-range@/nsg/a",
		"cloud.azure.nsg.open-ssh":                 "ssh-any@/nsg/b",
		"cloud.azure.sql.public-network":           "/sql/open",
	}
	if len(got) != len(want) {
		t.Fatalf("want %d findings, got %v", len(want), ruleIDs(got))
	}
	for _, f := range got {
		loc, ok := want[f.RuleID]
		if !ok {
			t.Fatalf("unexpected finding %s", f.RuleID)
		}
		if f.Location != loc {
			t.Fatalf("%s location = %s, want %s", f.RuleID, f.Location, loc)
		}
		for _, ev := range f.Evidence {
			if ev.Kind == "" || ev.Location == "" {
				t.Fatalf("thin evidence %+v", f)
			}
		}
	}
}

func TestAzureTruncatesOnCheckFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/subscriptions/"+testSub, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"subscriptionId":"` + testSub + `"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"no"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	e := testEngine(t, srv)
	o := engine.Options{Profile: mustProfile(t, "standard"), Redactor: safety.NewRedactor(), Log: testLog()}
	var got []domain.Finding
	err := e.Run(context.Background(), azureTarget(), o, func(f domain.Finding) error {
		got = append(got, f)
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("want partial error, got %v (%v)", err, ruleIDs(got))
	}
	if len(got) != 1 || got[0].RuleID != "cloud.azure.inventory-truncated" {
		t.Fatalf("want one truncated finding, got %v", ruleIDs(got))
	}
}

func TestAzureHostAllowlist(t *testing.T) {
	c := newHTTPClient([]string{"127.0.0.1"}, time.Second)
	// Off-allowlist hosts refuse before any dial: no network is touched.
	if _, err := c.Get("https://evil.example/x"); err == nil {
		t.Fatal("off-allowlist host must refuse")
	} else if !safety.IsRefusal(err) {
		t.Fatalf("want refusal, got %v", err)
	}
	srv := mockARM(t)
	defer srv.Close()
	c2 := newHTTPClient([]string{"127.0.0.1"}, 5*time.Second)
	if _, err := c2.Get(srv.URL + "/subscriptions/" + testSub + "?api-version=2022-12-01"); err != nil {
		t.Fatalf("allowlisted mock host must pass: %v", err)
	}
}

func ruleIDs(fs []domain.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestAzureGateBindsSubscription(t *testing.T) {
	scope, err := safety.NewScope(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := safety.CloudIdentity{Provider: "azure", Account: testSub, Principal: "service-principal/ci", Source: "env"}
	gate := &safety.Gate{Scope: scope, Acknowledged: true,
		CloudIdentityAzure: func(context.Context, domain.Target) (safety.CloudIdentity, error) { return id, nil },
		CloudAccountsAzure: []string{testSub}}
	tgt := domain.Target{Type: domain.TargetCloud, Value: Scheme + "my-sub", Hostname: "my-sub", Raw: Scheme + "my-sub"}
	dec, err := gate.Decide(context.Background(), tgt, "plan")
	if err != nil {
		t.Fatal(err)
	}
	if dec.Target.Value != Scheme+testSub || dec.Target.Hostname != testSub {
		t.Fatalf("target not rewritten: %+v", dec.Target)
	}
	if dec.ConsentMethod != domain.ConsentCloudAllowlist {
		t.Fatalf("consent = %s", dec.ConsentMethod)
	}
	// A name allow-list entry does not match a different subscription.
	gate2 := &safety.Gate{Scope: scope, Acknowledged: true,
		CloudIdentityAzure: func(context.Context, domain.Target) (safety.CloudIdentity, error) { return id, nil },
		CloudAccountsAzure: []string{"other"},
		Consent:            func(context.Context, domain.Target, string) (bool, error) { return false, nil }}
	if _, err := gate2.Decide(context.Background(), tgt, "plan"); err == nil {
		t.Fatal("unlisted subscription must not pass")
	}
	// A non-UUID identity fails closed even when allow-listed.
	badID := id
	badID.Account = "not-a-uuid"
	gate3 := &safety.Gate{Scope: scope, Acknowledged: true,
		CloudIdentityAzure: func(context.Context, domain.Target) (safety.CloudIdentity, error) { return badID, nil },
		CloudAccountsAzure: []string{testSub}}
	if _, err := gate3.Decide(context.Background(), tgt, "plan"); err == nil {
		t.Fatal("non-UUID account must refuse")
	}
	// No Azure identity function means azure:// targets refuse.
	gate4 := &safety.Gate{Scope: scope, Acknowledged: true}
	if _, err := gate4.Decide(context.Background(), tgt, "plan"); err == nil {
		t.Fatal("missing identity function must refuse")
	}
}
