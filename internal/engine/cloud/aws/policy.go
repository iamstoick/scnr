package aws

import (
	"encoding/json"
	"sort"
)

// Operations is the complete list of API operations the engine issues
// (service:Operation). It drives `scnr config show --aws-policy` and is
// pinned to the sources by TestAWSOperationsAreReadOnly, so the published
// IAM policy cannot drift from what the code calls. Every entry matches
// readOnlyOp or credentialOps.
var Operations = []string{
	"cloudtrail:DescribeTrails",
	"cloudtrail:GetTrailStatus",
	"ec2:DescribeInstances",
	"ec2:DescribeRegions",
	"ec2:DescribeSecurityGroups",
	"ec2:DescribeVolumes",
	"ec2:GetEbsEncryptionByDefault",
	"iam:GetAccountPasswordPolicy",
	"iam:GetAccountSummary",
	"iam:GetLoginProfile",
	"iam:ListAccessKeys",
	"iam:ListMFADevices",
	"iam:ListUsers",
	"kms:DescribeKey",
	"kms:GetKeyRotationStatus",
	"kms:ListKeys",
	"rds:DescribeDBInstances",
	"s3:GetBucketAcl",
	"s3:GetBucketLogging",
	"s3:GetBucketPolicyStatus",
	"s3:GetBucketPublicAccessBlock",
	"s3:GetEncryptionConfiguration",
	"s3:ListAllMyBuckets",
	"sts:GetCallerIdentity",
}

// s3IAMActions maps S3 API operations to their IAM action names where
// the two differ.
var s3IAMActions = map[string]string{
	"s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
	"s3:GetBucketEncryption":  "s3:GetEncryptionConfiguration",
	"s3:ListBuckets":          "s3:ListAllMyBuckets",
}

// IAMAction returns the IAM action name for an API operation.
func IAMAction(op string) string {
	if a, ok := s3IAMActions[op]; ok {
		return a
	}
	return op
}

// IAMPolicyJSON renders the minimal scanner policy. The managed policy
// arn:aws:iam::aws:policy/SecurityAudit is a superset and also works.
func IAMPolicyJSON() string {
	actions := append([]string(nil), Operations...)
	sort.Strings(actions)
	doc := map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Sid":      "ScnrReadOnlyPosture",
			"Effect":   "Allow",
			"Action":   actions,
			"Resource": "*",
		}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b) + "\n"
}
