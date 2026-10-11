# Scanning an AWS account

`scnr scan aws://` (default credentials) or `scnr scan aws://<profile>` runs
read-only posture checks against one AWS account and reports them like any
other target: asset `aws:<account-id>`, locations are resource ARNs.

## Credentials

scnr builds its own credential chain and never runs credential helpers:

1. `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`)
2. `AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN` (CI, IRSA)
3. The named profile (or `AWS_PROFILE`, or `default`) from
   `~/.aws/config` / `~/.aws/credentials` (`AWS_CONFIG_FILE`,
   `AWS_SHARED_CREDENTIALS_FILE` honoured): static keys, or `role_arn` with
   `source_profile` or `credential_source = Environment`.
4. EC2 instance / ECS container credentials, only with
   `cloud.aws.instance_credentials: true` in `scnr.yaml` (audited).

Refused: `credential_process` (export credentials to the environment or use
a `role_arn` profile instead), AWS SSO profiles (run `aws sso login` then
`aws configure export-credentials --format env`), `AWS_ENDPOINT_URL`,
PrivateLink/VPC endpoints.

`scnr doctor` shows which source would be used without resolving anything.

When you scan a named profile (`aws://audit`), the native engine uses that
profile and ignores any `AWS_ACCESS_KEY_ID` in the environment — but prowler
inherits the environment and may prefer it over `-p`, ending up in a
different account. That is caught, not silent: every foreign finding is
dropped and reported as `prowler:account-mismatch`. To avoid the noise,
export only one credential set when scanning a named profile.

## Account binding

Before any check, scnr calls `sts:GetCallerIdentity`. The account must be
listed in `scnr.yaml`:

```yaml
cloud:
  aws:
    accounts: ["123456789012"]
    regions: ["eu-west-1", "us-east-1"]   # optional; default: enabled regions, max 20
```

or, interactively, you type the account id back when prompted. With
`--non-interactive` an unlisted account exits 3 (`E_CLOUD_ACCOUNT_NOT_ALLOWED`).
The identity is checked again at the end of the run.

## IAM policy for the scanner

The managed policy `arn:aws:iam::aws:policy/SecurityAudit` is sufficient. The
minimal explicit policy is printed by:

```
scnr config show --aws-policy
```

Its action list is generated from the operations the code issues and pinned
by a test, so it cannot drift from the checks.

## What is checked

IAM: root MFA, root access keys, console users without MFA, password policy
(missing / weak), access keys older than 90 days. S3: public buckets,
Block Public Access, default encryption, access logging. EC2: security
groups open to the world (SSH, RDP, all), default security groups with
rules, unencrypted EBS volumes, EBS encryption by default, IMDSv1. RDS:
public, unencrypted, no backups. CloudTrail: none, single-region, no log
validation, not logging. KMS: rotation disabled.

Evidence contains only ARNs, ids, flags, dates, ports and CIDRs. Tags, user
data, environment variables, policy documents and credentials are never
read into a report.

## Limits

Every API call is rate-limited (10/s per region; 20/s with `--profile deep`)
and counted against a budget (5,000 per scan; 20,000 deep). Inventory lists
stop at 100 pages or 10,000 items. Hitting a limit produces
`cloud.aws.inventory-truncated` and marks the engine `partial`, which also
means findings from earlier scans are not marked fixed by that run.

## prowler

When `prowler` (>= 4.0) is on `PATH`, `adapter:prowler` runs
`prowler aws -M json-ocsf -o <scratch> -F prowler -z -b --no-color [-p <profile>] [-f <regions>]`
after the native engine confirmed the account. Fixers, Security Hub / S3
uploads, Slack, Shodan and browser auth are forbidden flags. Checks that
overlap the native set dedupe onto the native rule id, so each
misconfiguration appears once. Findings prowler reports for another account
are dropped and surfaced as `prowler:account-mismatch`.
