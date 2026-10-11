package aws

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/gerald/scnr/internal/domain"
)

// S3 error codes that mean "not configured" rather than "failed".
const (
	errNoPublicAccessBlock = "NoSuchPublicAccessBlockConfiguration"
	errNoEncryption        = "ServerSideEncryptionConfigurationNotFoundError"
	errNoBucketPolicy      = "NoSuchBucketPolicy"
)

// Public ACL grantee groups.
const (
	allUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	authenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// checkS3: for every bucket, public policy/ACL, public access block,
// default encryption and access logging. Reads bucket names, booleans and
// grantee group URIs only; policy and ACL documents are never copied.
func checkS3(ctx context.Context, r *run, cl *clients) error {
	pager := s3.NewListBucketsPaginator(cl.s3, &s3.ListBucketsInput{})
	return pages(ctx, r.cov, "s3:ListBuckets", "", pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, b := range page.Buckets {
			if err := checkBucket(ctx, r, cl, aws.ToString(b.Name)); err != nil {
				return 0, err
			}
		}
		return len(page.Buckets), nil
	})
}

func checkBucket(ctx context.Context, r *run, cl *clients, name string) error {
	if name == "" {
		return nil
	}
	arn := "arn:aws:s3:::" + name
	in := aws.String(name)

	// Public: by policy status or by ACL group grant.
	var why []string
	ps, err := cl.s3.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: in})
	switch {
	case err == nil:
		if ps.PolicyStatus != nil && aws.ToBool(ps.PolicyStatus.IsPublic) {
			why = append(why, "PolicyStatus.IsPublic=true")
		}
	case apiErrorCode(err) == errNoBucketPolicy:
	default:
		return err
	}
	acl, err := cl.s3.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: in})
	if err != nil {
		return err
	}
	for _, g := range acl.Grants {
		if g.Grantee == nil {
			continue
		}
		switch aws.ToString(g.Grantee.URI) {
		case allUsersURI:
			why = append(why, "ACL grants "+string(g.Permission)+" to AllUsers")
		case authenticatedUsersURI:
			why = append(why, "ACL grants "+string(g.Permission)+" to AuthenticatedUsers")
		}
	}
	if len(why) > 0 {
		if err := r.finding(RuleBucketPublic, arn, domain.Confirmed, strings.Join(why, "; ")); err != nil {
			return err
		}
	}

	// Public access block: missing or any of the four flags off.
	pab, err := cl.s3.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: in})
	switch {
	case err == nil:
		c := pab.PublicAccessBlockConfiguration
		if c == nil || !aws.ToBool(c.BlockPublicAcls) || !aws.ToBool(c.IgnorePublicAcls) || !aws.ToBool(c.BlockPublicPolicy) || !aws.ToBool(c.RestrictPublicBuckets) {
			summary := "PublicAccessBlock present but incomplete"
			if c != nil {
				summary = fmt.Sprintf("BlockPublicAcls=%t IgnorePublicAcls=%t BlockPublicPolicy=%t RestrictPublicBuckets=%t", aws.ToBool(c.BlockPublicAcls), aws.ToBool(c.IgnorePublicAcls), aws.ToBool(c.BlockPublicPolicy), aws.ToBool(c.RestrictPublicBuckets))
			}
			if err := r.finding(RulePublicAccessBlockMissing, arn, domain.Confirmed, summary); err != nil {
				return err
			}
		}
	case apiErrorCode(err) == errNoPublicAccessBlock:
		if err := r.finding(RulePublicAccessBlockMissing, arn, domain.Confirmed, "GetPublicAccessBlock="+errNoPublicAccessBlock); err != nil {
			return err
		}
	default:
		return err
	}

	// Default encryption.
	if _, err := cl.s3.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: in}); err != nil {
		if apiErrorCode(err) != errNoEncryption {
			return err
		}
		if err := r.finding(RuleBucketEncryptionDisabled, arn, domain.Confirmed, "GetBucketEncryption="+errNoEncryption); err != nil {
			return err
		}
	}

	// Access logging.
	lg, err := cl.s3.GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: in})
	if err != nil {
		return err
	}
	if lg.LoggingEnabled == nil {
		return r.finding(RuleBucketLoggingDisabled, arn, domain.Confirmed, "LoggingEnabled absent")
	}
	return nil
}
