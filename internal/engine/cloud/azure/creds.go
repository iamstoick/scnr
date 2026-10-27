package azure

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Credential sources. Only two exist: an environment service principal
// or the VM managed identity when the scope file allows it. Nothing
// interactive, no browser, no shared token cache.
const (
	SourceEnv             = "env"
	SourceManagedIdentity = "managed-identity"
)

// TokenScope is the only scope ever requested: ARM, nothing else.
const TokenScope = "https://management.azure.com/.default"

// refuse builds a credential refusal that never echoes a secret.
func refuse(reason string) error {
	return fmt.Errorf("azure credentials: %s (set AZURE_CLIENT_ID, AZURE_TENANT_ID and AZURE_CLIENT_SECRET, or enable cloud.azure.managed_identity)", reason)
}

// tokenHosts are the login endpoints a token request may go to.
func (e *Engine) tokenHosts() []string {
	if e.BaseEndpoint != "" {
		return e.EndpointHosts
	}
	return []string{"login.microsoftonline.com"}
}

// tokenURL is the Entra token endpoint, or the mock server in tests.
func (e *Engine) tokenURL(tenant string) string {
	if e.BaseEndpoint != "" {
		return e.BaseEndpoint + "/" + tenant + "/oauth2/v2.0/token"
	}
	return "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
}

// credential resolves exactly one login: an environment service principal
// or the managed identity when the scope file allows it. Anything else is
// a refusal, and the password value never appears in an error.
func (e *Engine) credential() (tokenSource, string, error) {
	if e.testCred != nil {
		return e.testCred, e.testSource, nil
	}
	clientID := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	tenantID := strings.TrimSpace(os.Getenv("AZURE_TENANT_ID"))
	secret := os.Getenv("AZURE_CLIENT_SECRET")
	switch {
	case clientID != "" || tenantID != "" || secret != "":
		if clientID == "" || tenantID == "" || secret == "" {
			return nil, "", refuse("partial service-principal environment")
		}
		client := newHTTPClient(e.tokenHosts(), time.Minute)
		return &clientSecretCredential{
			client: client, tokenURL: e.tokenURL(tenantID),
			clientID: clientID, tenantID: tenantID, secret: secret,
		}, SourceEnv, nil
	case e.Config.ManagedIdentity:
		endpoint := "http://169.254.169.254"
		hosts := []string{"169.254.169.254"}
		if e.BaseEndpoint != "" {
			endpoint = e.BaseEndpoint
			hosts = e.EndpointHosts
		}
		client := newHTTPClient(hosts, time.Minute)
		return &managedIdentityCredential{
			client: client, endpoint: endpoint, resource: "https://management.azure.com/",
		}, SourceManagedIdentity, nil
	default:
		return nil, "", refuse("no service principal in the environment")
	}
}

// principalName renders the login for consent and audit lines: the client
// id for a service principal, never the secret.
func principalName(source string) string {
	if source == SourceEnv {
		if id := strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID")); id != "" {
			return "service-principal/" + id
		}
	}
	return source
}
