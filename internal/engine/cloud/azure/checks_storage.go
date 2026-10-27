package azure

import (
	"context"
	"fmt"
	"strings"
)

// storageAccount is the subset of the ARM model the checks read: network
// exposure and TLS floor. Nothing else is fetched or stored.
type storageAccount struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PublicNetworkAccess   string `json:"publicNetworkAccess"`
		AllowBlobPublicAccess *bool  `json:"allowBlobPublicAccess"`
		MinimumTLSVersion     string `json:"minimumTlsVersion"`
	} `json:"properties"`
}

func listStorageAccounts(ctx context.Context, r *run, emit func(storageAccount) error) error {
	return armList(ctx, r.s, "/subscriptions/"+r.sub+"/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01",
		func(page []storageAccount) error {
			for _, a := range page {
				if err := emit(a); err != nil {
					return err
				}
			}
			return nil
		})
}

// checkStorageBlobPublic flags accounts whose blobs can be anonymous: the
// classic public-container takeover and data leak.
func checkStorageBlobPublic(ctx context.Context, r *run) error {
	return listStorageAccounts(ctx, r, func(a storageAccount) error {
		if a.Properties.AllowBlobPublicAccess != nil && *a.Properties.AllowBlobPublicAccess {
			return r.finding("cloud.azure.storage.blob-public", a.ID,
				fmt.Sprintf("storage account %q allows anonymous blob access", a.Name))
		}
		return nil
	})
}

// checkStoragePublicNetwork flags accounts reachable from the internet at
// the firewall level.
func checkStoragePublicNetwork(ctx context.Context, r *run) error {
	return listStorageAccounts(ctx, r, func(a storageAccount) error {
		if strings.EqualFold(a.Properties.PublicNetworkAccess, "Enabled") {
			return r.finding("cloud.azure.storage.public-network", a.ID,
				fmt.Sprintf("storage account %q allows public network access", a.Name))
		}
		return nil
	})
}

// checkStorageMinTLS flags accounts still negotiating TLS 1.0/1.1.
func checkStorageMinTLS(ctx context.Context, r *run) error {
	return listStorageAccounts(ctx, r, func(a storageAccount) error {
		switch strings.ToUpper(strings.ReplaceAll(a.Properties.MinimumTLSVersion, " ", "")) {
		case "TLS1_0", "TLS1_1", "TLS1.0", "TLS1.1":
			return r.finding("cloud.azure.storage.min-tls", a.ID,
				fmt.Sprintf("storage account %q allows %s", a.Name, a.Properties.MinimumTLSVersion))
		}
		return nil
	})
}
