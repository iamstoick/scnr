package azure

import (
	"context"
	"fmt"
	"strings"
)

// sqlServer is the subset of the ARM model the check reads: network
// exposure. Databases, logins and firewall rules are out of scope.
type sqlServer struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PublicNetworkAccess string `json:"publicNetworkAccess"`
		MinimalTLSVersion   string `json:"minimalTlsVersion"`
	} `json:"properties"`
}

// checkSQLPublicNetwork flags SQL servers reachable from the internet:
// databases should sit behind private endpoints.
func checkSQLPublicNetwork(ctx context.Context, r *run) error {
	return armList(ctx, r.s, "/subscriptions/"+r.sub+"/providers/Microsoft.Sql/servers?api-version=2023-05-01-preview",
		func(page []sqlServer) error {
			for _, s := range page {
				if strings.EqualFold(s.Properties.PublicNetworkAccess, "Enabled") {
					return r.finding("cloud.azure.sql.public-network", s.ID,
						fmt.Sprintf("SQL server %q allows public network access", s.Name))
				}
			}
			return nil
		})
}
