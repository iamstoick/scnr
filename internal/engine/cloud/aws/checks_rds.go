package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/gerald/scnr/internal/domain"
)

// checkRDS: publicly accessible, unencrypted storage, backups disabled.
// Reads the instance ARN, identifier and three flags; never the master
// username, endpoint or tags.
func checkRDS(ctx context.Context, r *run, cl *clients) error {
	pager := rds.NewDescribeDBInstancesPaginator(cl.rds, &rds.DescribeDBInstancesInput{})
	return pages(ctx, r.cov, "rds:DescribeDBInstances", cl.region, pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, db := range page.DBInstances {
			arn := aws.ToString(db.DBInstanceArn)
			if arn == "" {
				arn = fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", cl.region, r.account, aws.ToString(db.DBInstanceIdentifier))
			}
			if aws.ToBool(db.PubliclyAccessible) {
				if err := r.finding(RuleRDSPublic, arn, domain.Confirmed, "PubliclyAccessible=true"); err != nil {
					return 0, err
				}
			}
			if !aws.ToBool(db.StorageEncrypted) {
				if err := r.finding(RuleRDSUnencrypted, arn, domain.Confirmed, "StorageEncrypted=false"); err != nil {
					return 0, err
				}
			}
			if aws.ToInt32(db.BackupRetentionPeriod) == 0 {
				if err := r.finding(RuleRDSBackupsDisabled, arn, domain.Confirmed, "BackupRetentionPeriod=0"); err != nil {
					return 0, err
				}
			}
		}
		return len(page.DBInstances), nil
	})
}
