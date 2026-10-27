package azure

import (
	"context"
	"fmt"
	"strings"
)

// keyVault is the subset of the ARM model the checks read: network
// exposure and deletion safety. Secret values are never listed or read.
type keyVault struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PublicNetworkAccess   string `json:"publicNetworkAccess"`
		EnablePurgeProtection *bool  `json:"enablePurgeProtection"`
		EnableSoftDelete      *bool  `json:"enableSoftDelete"`
	} `json:"properties"`
}

func listKeyVaults(ctx context.Context, r *run, emit func(keyVault) error) error {
	return armList(ctx, r.s, "/subscriptions/"+r.sub+"/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01",
		func(page []keyVault) error {
			for _, v := range page {
				if err := emit(v); err != nil {
					return err
				}
			}
			return nil
		})
}

// checkKeyVaultPublicNetwork flags vaults reachable from the internet:
// keys, secrets and certificates should sit behind private endpoints.
func checkKeyVaultPublicNetwork(ctx context.Context, r *run) error {
	return listKeyVaults(ctx, r, func(v keyVault) error {
		if strings.EqualFold(v.Properties.PublicNetworkAccess, "Enabled") {
			return r.finding("cloud.azure.keyvault.public-network", v.ID,
				fmt.Sprintf("key vault %q allows public network access", v.Name))
		}
		return nil
	})
}

// checkKeyVaultPurgeProtection flags vaults where a deleted vault (and
// everything in it) can be purged immediately: no recovery window.
func checkKeyVaultPurgeProtection(ctx context.Context, r *run) error {
	return listKeyVaults(ctx, r, func(v keyVault) error {
		if v.Properties.EnablePurgeProtection != nil && !*v.Properties.EnablePurgeProtection {
			return r.finding("cloud.azure.keyvault.no-purge-protection", v.ID,
				fmt.Sprintf("key vault %q has purge protection off", v.Name))
		}
		return nil
	})
}
