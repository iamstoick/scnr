package azure

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Credential sources. Only these two exist: there is no browser login,
// no device-code flow, no shared token cache — nothing interactive and
// nothing that opens a browser.
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

// credential resolves exactly one login: an environment service principal,
// or the VM managed identity when the scope file allows it. Anything else
// is a refusal, and the password value never appears in an error.
func (e *Engine) credential() (azcore.TokenCredential, string, error) {
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
		cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, secret, nil)
		if err != nil {
			return nil, "", refuse("service-principal rejected")
		}
		return cred, SourceEnv, nil
	case e.Config.ManagedIdentity:
		cred, err := azidentity.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, "", refuse("managed identity unavailable")
		}
		return cred, SourceManagedIdentity, nil
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

var errNoCredential = errors.New("no credential")
