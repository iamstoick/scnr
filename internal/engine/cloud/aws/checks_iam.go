package aws

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/gerald/scnr/internal/domain"
)

// Password-policy and key-age thresholds.
const (
	minPasswordLength = 14
	maxAccessKeyAge   = 90 * 24 * time.Hour
)

// checkIAM: root MFA and keys, console users without MFA, stale access
// keys, account password policy. Reads only names, ARNs, dates and flags.
func checkIAM(ctx context.Context, r *run, cl *clients) error {
	root := fmt.Sprintf("arn:aws:iam::%s:root", r.account)
	sum, err := cl.iam.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return err
	}
	if sum.SummaryMap["AccountMFAEnabled"] == 0 {
		if err := r.finding(RuleRootMFADisabled, root, domain.Confirmed, "AccountMFAEnabled=0"); err != nil {
			return err
		}
	}
	if n := sum.SummaryMap["AccountAccessKeysPresent"]; n > 0 {
		if err := r.finding(RuleRootAccessKeys, root, domain.Confirmed, fmt.Sprintf("AccountAccessKeysPresent=%d", n)); err != nil {
			return err
		}
	}
	if err := checkPasswordPolicy(ctx, r, cl, root); err != nil {
		return err
	}
	now := time.Now()
	pager := iam.NewListUsersPaginator(cl.iam, &iam.ListUsersInput{})
	return pages(ctx, r.cov, "iam:ListUsers", "", pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, u := range page.Users {
			if err := checkUser(ctx, r, cl, u, now); err != nil {
				return 0, err
			}
		}
		return len(page.Users), nil
	})
}

func checkPasswordPolicy(ctx context.Context, r *run, cl *clients, root string) error {
	pp, err := cl.iam.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	var nse *types.NoSuchEntityException
	if errors.As(err, &nse) {
		return r.finding(RulePasswordPolicyMissing, root, domain.Confirmed, "GetAccountPasswordPolicy=NoSuchEntity")
	}
	if err != nil {
		return err
	}
	p := pp.PasswordPolicy
	if p == nil {
		return nil
	}
	minLen := aws.ToInt32(p.MinimumPasswordLength)
	maxAge := aws.ToInt32(p.MaxPasswordAge)
	if minLen < minPasswordLength || !p.RequireSymbols || !p.RequireNumbers || !p.RequireUppercaseCharacters || !p.RequireLowercaseCharacters || maxAge == 0 {
		return r.finding(RulePasswordPolicyWeak, root, domain.Confirmed,
			fmt.Sprintf("MinimumPasswordLength=%d RequireSymbols=%t RequireNumbers=%t RequireUppercase=%t RequireLowercase=%t MaxPasswordAge=%d", minLen, p.RequireSymbols, p.RequireNumbers, p.RequireUppercaseCharacters, p.RequireLowercaseCharacters, maxAge))
	}
	return nil
}

// checkUser inspects one IAM user: console password without MFA, and
// active access keys older than 90 days.
func checkUser(ctx context.Context, r *run, cl *clients, u types.User, now time.Time) error {
	name, arn := aws.ToString(u.UserName), aws.ToString(u.Arn)
	if name == "" || arn == "" {
		return nil
	}
	_, err := cl.iam.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: u.UserName})
	var nse *types.NoSuchEntityException
	hasConsole := err == nil
	if err != nil && !errors.As(err, &nse) {
		return err
	}
	if hasConsole {
		mfa, err := cl.iam.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: u.UserName})
		if err != nil {
			return err
		}
		if len(mfa.MFADevices) == 0 {
			if err := r.finding(RuleUserWithoutMFA, arn, domain.Confirmed, "console password present, MFADevices=0"); err != nil {
				return err
			}
		}
	}
	keys, err := cl.iam.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: u.UserName})
	if err != nil {
		return err
	}
	for _, k := range keys.AccessKeyMetadata {
		if k.Status != types.StatusTypeActive || k.CreateDate == nil {
			continue
		}
		if age := now.Sub(*k.CreateDate); age > maxAccessKeyAge {
			// The key id is a credential identifier: the summary carries
			// its age only.
			if err := r.finding(RuleAccessKeyStale, arn, domain.Confirmed, fmt.Sprintf("active access key created %s (%d days ago)", k.CreateDate.UTC().Format("2006-01-02"), int(age.Hours()/24))); err != nil {
				return err
			}
		}
	}
	return nil
}
