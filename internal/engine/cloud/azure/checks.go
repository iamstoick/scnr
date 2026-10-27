package azure

import "context"

// check is one read-only posture probe.
type check struct {
	name string
	fn   func(ctx context.Context, r *run) error
}

// checks runs storage, vault, network and SQL probes, cheapest first.
var checks = []check{
	{"storage-blob-public", checkStorageBlobPublic},
	{"storage-public-network", checkStoragePublicNetwork},
	{"storage-min-tls", checkStorageMinTLS},
	{"keyvault-public-network", checkKeyVaultPublicNetwork},
	{"keyvault-purge-protection", checkKeyVaultPurgeProtection},
	{"nsg-open-rdp", checkNSGOpenRDP},
	{"nsg-open-ssh", checkNSGOpenSSH},
	{"sql-public-network", checkSQLPublicNetwork},
}

func checkNames() []string {
	out := make([]string, 0, len(checks))
	for _, c := range checks {
		out = append(out, c.name)
	}
	return out
}
