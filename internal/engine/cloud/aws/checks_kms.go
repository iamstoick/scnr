package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/gerald/scnr/internal/domain"
)

// checkKMS: customer-managed symmetric keys without automatic rotation.
// Reads key ARNs and the manager/state/spec/origin enums only; never the
// key description or tags.
func checkKMS(ctx context.Context, r *run, cl *clients) error {
	pager := kms.NewListKeysPaginator(cl.kms, &kms.ListKeysInput{})
	return pages(ctx, r.cov, "kms:ListKeys", cl.region, pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, k := range page.Keys {
			if err := checkKey(ctx, r, cl, k); err != nil {
				return 0, err
			}
		}
		return len(page.Keys), nil
	})
}

func checkKey(ctx context.Context, r *run, cl *clients, k types.KeyListEntry) error {
	arn := aws.ToString(k.KeyArn)
	if arn == "" || k.KeyId == nil {
		return nil
	}
	d, err := cl.kms.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
	if err != nil {
		return err
	}
	m := d.KeyMetadata
	if m == nil || m.KeyManager != types.KeyManagerTypeCustomer || m.KeyState != types.KeyStateEnabled || m.KeySpec != types.KeySpecSymmetricDefault || m.Origin != types.OriginTypeAwsKms {
		return nil // rotation applies to enabled, customer-managed, symmetric, KMS-origin keys only
	}
	rot, err := cl.kms.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: k.KeyId})
	if err != nil {
		return err
	}
	if !rot.KeyRotationEnabled {
		return r.finding(RuleKMSRotationDisabled, arn, domain.Confirmed, "KeyRotationEnabled=false KeyManager=CUSTOMER KeySpec=SYMMETRIC_DEFAULT")
	}
	return nil
}
