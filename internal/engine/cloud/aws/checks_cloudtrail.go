package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"

	"github.com/iamstoick/scnr/internal/domain"
)

// checkCloudTrail: no trail at all, trails that are single-region, without
// log file validation, or not logging. DescribeTrails returns every trail
// of the account (shadow trails included), so this runs once globally.
// Reads trail ARNs and flags only; never the S3 bucket name or prefix.
func checkCloudTrail(ctx context.Context, r *run, cl *clients) error {
	out, err := cl.ct.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return err
	}
	if len(out.TrailList) == 0 {
		return r.finding(RuleTrailMissing, fmt.Sprintf("arn:aws:iam::%s:root", r.account), domain.Confirmed, "DescribeTrails returned no trails")
	}
	for _, t := range out.TrailList {
		arn := aws.ToString(t.TrailARN)
		if arn == "" {
			continue
		}
		if !aws.ToBool(t.IsMultiRegionTrail) {
			if err := r.finding(RuleTrailNotMultiRegion, arn, domain.Confirmed, "IsMultiRegionTrail=false"); err != nil {
				return err
			}
		}
		if !aws.ToBool(t.LogFileValidationEnabled) {
			if err := r.finding(RuleTrailValidationDisabled, arn, domain.Confirmed, "LogFileValidationEnabled=false"); err != nil {
				return err
			}
		}
		st, err := cl.ct.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: t.TrailARN})
		if err != nil {
			return err
		}
		if !aws.ToBool(st.IsLogging) {
			if err := r.finding(RuleTrailNotLogging, arn, domain.Confirmed, "IsLogging=false"); err != nil {
				return err
			}
		}
	}
	return nil
}
