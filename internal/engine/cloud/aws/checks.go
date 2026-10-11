package aws

import (
	"context"
	"errors"
	"regexp"

	"github.com/aws/smithy-go"
)

// Rule IDs (rules/aws.yaml carries the prose).
const (
	RuleInventoryTruncated = "cloud.aws.inventory-truncated"

	RuleRootMFADisabled       = "cloud.aws.iam.root-mfa-disabled"
	RuleRootAccessKeys        = "cloud.aws.iam.root-access-keys"
	RuleUserWithoutMFA        = "cloud.aws.iam.user-without-mfa"
	RulePasswordPolicyMissing = "cloud.aws.iam.password-policy-missing"
	RulePasswordPolicyWeak    = "cloud.aws.iam.password-policy-weak"
	RuleAccessKeyStale        = "cloud.aws.iam.access-key-stale"

	RuleBucketPublic             = "cloud.aws.s3.bucket-public"
	RulePublicAccessBlockMissing = "cloud.aws.s3.public-access-block-missing"
	RuleBucketEncryptionDisabled = "cloud.aws.s3.encryption-disabled"
	RuleBucketLoggingDisabled    = "cloud.aws.s3.logging-disabled"

	RuleSGOpenSSH              = "cloud.aws.ec2.sg-open-ssh"
	RuleSGOpenRDP              = "cloud.aws.ec2.sg-open-rdp"
	RuleSGOpenAll              = "cloud.aws.ec2.sg-open-all"
	RuleDefaultSGAllowsTraffic = "cloud.aws.ec2.default-sg-allows-traffic"
	RuleEBSVolumeUnencrypted   = "cloud.aws.ec2.ebs-volume-unencrypted"
	RuleEBSDefaultEncryption   = "cloud.aws.ec2.ebs-default-encryption-off"
	RuleIMDSv1Allowed          = "cloud.aws.ec2.imdsv1-allowed"

	RuleRDSPublic          = "cloud.aws.rds.publicly-accessible"
	RuleRDSUnencrypted     = "cloud.aws.rds.storage-unencrypted"
	RuleRDSBackupsDisabled = "cloud.aws.rds.backups-disabled"

	RuleTrailMissing            = "cloud.aws.cloudtrail.missing"
	RuleTrailNotMultiRegion     = "cloud.aws.cloudtrail.not-multi-region"
	RuleTrailValidationDisabled = "cloud.aws.cloudtrail.validation-disabled"
	RuleTrailNotLogging         = "cloud.aws.cloudtrail.not-logging"

	RuleKMSRotationDisabled = "cloud.aws.kms.rotation-disabled"
)

var (
	accountIDRe = regexp.MustCompile(`^[0-9]{12}$`)
	regionRe    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// check is one posture check. fn may only read allowlisted fields (ARNs,
// ids, names, booleans, dates, ports, CIDRs, status flags) into findings:
// never tags, user data, environment, policy documents, descriptions or
// master usernames (TestNoForbiddenFieldsInEvidence pins the sources).
type check struct {
	name string
	fn   func(ctx context.Context, r *run, cl *clients) error
}

// globalChecks run once against the global region; regionalChecks run in
// every selected region.
var (
	globalChecks   = []check{{"iam", checkIAM}, {"s3", checkS3}, {"cloudtrail", checkCloudTrail}}
	regionalChecks = []check{{"ec2", checkEC2}, {"rds", checkRDS}, {"kms", checkKMS}}
)

func checkNames() []string {
	var out []string
	for _, c := range append(append([]check(nil), globalChecks...), regionalChecks...) {
		out = append(out, c.name)
	}
	return out
}

// apiErrorCode returns the service error code of err ("" when it is not a
// modelled API error).
func apiErrorCode(err error) string {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	return ""
}
