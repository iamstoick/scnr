package azure

import (
	"context"
	"fmt"
)

// subscription previews one subscription: the exactly-one identity call
// the gate requires before any check runs.
func (s *session) subscription(ctx context.Context, sub string) (string, string, error) {
	var got struct {
		SubscriptionID string `json:"subscriptionId"`
		TenantID       string `json:"tenantId"`
		State          string `json:"state"`
	}
	if err := s.armGet(ctx, "/subscriptions/"+sub+"?api-version=2022-12-01", &got); err != nil {
		if isNotFound(err) {
			return "", "", fmt.Errorf("azure identity: subscription not found or these credentials cannot read it")
		}
		return "", "", fmt.Errorf("azure identity: %w", err)
	}
	if got.SubscriptionID == "" {
		return "", "", fmt.Errorf("azure identity: no subscription in the identity response")
	}
	return got.SubscriptionID, got.TenantID, nil
}
