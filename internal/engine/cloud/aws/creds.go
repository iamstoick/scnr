package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"

	"github.com/gerald/scnr/internal/safety"
)

// Credential source labels (safety.CloudIdentity.Source).
const (
	SourceEnv         = "env"
	SourceWebIdentity = "web-identity"
	SourceInstance    = "instance"
	sourceProfile     = "profile:"
)

// maxRoleChain bounds source_profile nesting (role_arn whose source is
// itself a role_arn profile).
const maxRoleChain = 2

// profileRe validates a profile name from the target (aws://<profile>).
var profileRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// metadataHosts are the only destinations the instance-credential client
// may reach: EC2 IMDS and the ECS container credential endpoint.
var metadataHosts = []string{"169.254.169.254", "169.254.170.2"}

// credentialProcessHint is the refusal text for credential_process profiles.
const credentialProcessHint = "scnr does not run credential helpers; export credentials to the environment or use a role_arn profile"

// credPlan describes where credentials come from without resolving any.
// doctor prints the description; the engine builds the provider.
type credPlan struct {
	source string // SourceEnv | SourceWebIdentity | profile:<name> | SourceInstance
	kind   string // "static" | "web-identity" | "assume-role" | "instance"
	// static
	key, secret, token string
	// web identity / assume role
	roleARN, tokenFile, sessionName string
	externalID                      *string
	// assume-role source (nested plan, depth <= maxRoleChain)
	src *credPlan
	// instance credentials
	containerURL string
}

// Describe is the human-readable chain description (no secrets).
func (p *credPlan) Describe() string {
	switch p.kind {
	case "assume-role":
		return fmt.Sprintf("%s (role %s via %s)", p.source, p.roleARN, p.src.Describe())
	case "web-identity":
		return fmt.Sprintf("%s (role %s, token file %s)", p.source, p.roleARN, p.tokenFile)
	}
	return p.source
}

// chainOptions is what the planner needs from the scope file.
type chainOptions struct {
	instanceCredentials bool
}

// refuse builds the E_CLOUD_CREDENTIAL_SOURCE refusal.
func refuse(profile, reason string) error {
	return &safety.RefusalError{Code: safety.CodeCloudCredentialSource, Target: "aws://" + profile, Reason: reason}
}

// planCredentials walks the explicit chain (spec 3.3): environment keys,
// web identity, the named (or default) shared-config profile, then
// instance credentials when enabled. It reads env and files only and
// never runs a helper. config.LoadDefaultConfig is deliberately not used:
// it would add credential_process, SSO, AWS_ENDPOINT_URL and IMDS region
// lookups to the chain.
func planCredentials(ctx context.Context, profile string, o chainOptions) (*credPlan, error) {
	if profile != "" && !profileRe.MatchString(profile) {
		return nil, refuse(profile, "invalid profile name")
	}
	if profile == "" {
		if p := envStatic(); p != nil {
			return p, nil
		}
		if p, err := envWebIdentity(); p != nil || err != nil {
			return p, err
		}
	}
	name := profile
	if name == "" {
		name = os.Getenv("AWS_PROFILE")
	}
	if name == "" {
		name = "default"
	}
	sc, err := loadProfile(ctx, name)
	switch {
	case err == nil:
		return profilePlan(ctx, sc, name, o, 0)
	case profile != "" || os.Getenv("AWS_PROFILE") != "":
		// A profile was asked for by name: its absence is an error, not a
		// reason to fall through to instance credentials.
		return nil, refuse(name, err.Error())
	}
	if o.instanceCredentials {
		return instancePlan(), nil
	}
	return nil, refuse(profile, "no credentials found: set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, AWS_WEB_IDENTITY_TOKEN_FILE/AWS_ROLE_ARN, or a shared-config profile (cloud.aws.instance_credentials enables IMDS/ECS credentials)")
}

func envStatic() *credPlan {
	key, secret := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")
	if key == "" || secret == "" {
		return nil
	}
	return &credPlan{source: SourceEnv, kind: "static", key: key, secret: secret, token: os.Getenv("AWS_SESSION_TOKEN")}
}

func envWebIdentity() (*credPlan, error) {
	file, role := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"), os.Getenv("AWS_ROLE_ARN")
	if file == "" && role == "" {
		return nil, nil
	}
	if file == "" || role == "" {
		return nil, refuse("", "AWS_WEB_IDENTITY_TOKEN_FILE and AWS_ROLE_ARN must both be set")
	}
	return &credPlan{source: SourceWebIdentity, kind: "web-identity", roleARN: role, tokenFile: file, sessionName: os.Getenv("AWS_ROLE_SESSION_NAME")}, nil
}

// loadProfile reads the named profile from the shared config/credentials
// files (AWS_CONFIG_FILE / AWS_SHARED_CREDENTIALS_FILE honoured). The SDK
// loader resolves source_profile into SharedConfig.Source for us.
func loadProfile(ctx context.Context, name string) (config.SharedConfig, error) {
	return config.LoadSharedConfigProfile(ctx, name, func(o *config.LoadSharedConfigOptions) {
		if f := os.Getenv("AWS_CONFIG_FILE"); f != "" {
			o.ConfigFiles = []string{f}
		}
		if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
			o.CredentialsFiles = []string{f}
		}
	})
}

// profilePlan inspects one shared-config profile. Refused outright:
// credential_process (arbitrary command execution), sso_* (open question
// 1: no in 4b) and instance/container credential_source without the
// scope-file flag.
func profilePlan(ctx context.Context, sc config.SharedConfig, name string, o chainOptions, depth int) (*credPlan, error) {
	source := sourceProfile + name
	switch {
	case sc.CredentialProcess != "":
		return nil, refuse(name, "profile uses credential_process; "+credentialProcessHint)
	case sc.SSOStartURL != "" || sc.SSOSession != nil || sc.SSOSessionName != "" || sc.SSOAccountID != "" || sc.SSORoleName != "":
		return nil, refuse(name, "profile uses AWS SSO, which scnr does not support; run `aws sso login` then `aws configure export-credentials --format env` and scan with the exported environment")
	case sc.Credentials.HasKeys():
		return &credPlan{source: source, kind: "static", key: sc.Credentials.AccessKeyID, secret: sc.Credentials.SecretAccessKey, token: sc.Credentials.SessionToken}, nil
	case sc.RoleARN != "" && sc.WebIdentityTokenFile != "":
		return &credPlan{source: source, kind: "web-identity", roleARN: sc.RoleARN, tokenFile: sc.WebIdentityTokenFile, sessionName: sc.RoleSessionName}, nil
	case sc.RoleARN != "":
		if depth >= maxRoleChain {
			return nil, refuse(name, fmt.Sprintf("role_arn chain deeper than %d profiles", maxRoleChain))
		}
		var src *credPlan
		var err error
		switch {
		case sc.Source != nil:
			src, err = profilePlan(ctx, *sc.Source, sc.SourceProfileName, o, depth+1)
		case strings.EqualFold(sc.CredentialSource, "Environment"):
			if src = envStatic(); src == nil {
				err = refuse(name, "credential_source = Environment but AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set")
			}
		case strings.EqualFold(sc.CredentialSource, "Ec2InstanceMetadata") || strings.EqualFold(sc.CredentialSource, "EcsContainer"):
			if !o.instanceCredentials {
				return nil, refuse(name, "profile uses credential_source = "+sc.CredentialSource+"; set cloud.aws.instance_credentials: true in scnr.yaml to allow instance credentials (audited)")
			}
			src = instancePlan()
		default:
			err = refuse(name, "role_arn profile needs source_profile or credential_source")
		}
		if err != nil {
			return nil, err
		}
		var ext *string
		if sc.ExternalID != "" {
			ext = aws.String(sc.ExternalID)
		}
		return &credPlan{source: source, kind: "assume-role", roleARN: sc.RoleARN, sessionName: sc.RoleSessionName, externalID: ext, src: src}, nil
	case strings.EqualFold(sc.CredentialSource, "Ec2InstanceMetadata") || strings.EqualFold(sc.CredentialSource, "EcsContainer"):
		if !o.instanceCredentials {
			return nil, refuse(name, "profile uses credential_source = "+sc.CredentialSource+" without role_arn; set cloud.aws.instance_credentials: true to allow instance credentials")
		}
		return instancePlan(), nil
	}
	return nil, refuse(name, "profile has no usable credentials (aws_access_key_id/aws_secret_access_key or role_arn)")
}

func instancePlan() *credPlan {
	p := &credPlan{source: SourceInstance, kind: "instance"}
	if u := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); u != "" {
		p.containerURL = u
	} else if rel := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		p.containerURL = "http://169.254.170.2" + rel
	}
	return p
}

// provider turns a plan into the SDK credential provider. s supplies the
// STS client for AssumeRole* and the HTTP client factory for IMDS.
func (p *credPlan) provider(s *session, ua string) (aws.CredentialsProvider, error) {
	switch p.kind {
	case "static":
		return credentials.NewStaticCredentialsProvider(p.key, p.secret, p.token), nil
	case "web-identity":
		return stscreds.NewWebIdentityRoleProvider(s.stsClient(aws.AnonymousCredentials{}), p.roleARN, stscreds.IdentityTokenFile(p.tokenFile), func(o *stscreds.WebIdentityRoleOptions) {
			o.RoleSessionName = p.sessionName
		}), nil
	case "assume-role":
		src, err := p.src.provider(s, ua)
		if err != nil {
			return nil, err
		}
		return stscreds.NewAssumeRoleProvider(s.stsClient(aws.NewCredentialsCache(src)), p.roleARN, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = p.sessionName
			o.ExternalID = p.externalID
		}), nil
	case "instance":
		return p.instanceProvider(ua)
	}
	return nil, errors.New("cloud/aws: unknown credential plan")
}

// instanceProvider builds the IMDS/ECS provider over an endpoint client
// that admits exactly the metadata hosts (the one place BuiltinDeny is set
// aside; the caller audits it).
func (p *credPlan) instanceProvider(ua string) (aws.CredentialsProvider, error) {
	hosts := append([]string(nil), metadataHosts...)
	if p.containerURL != "" {
		h := safety.URLHost(p.containerURL)
		if h == "" {
			return nil, refuse("", "AWS_CONTAINER_CREDENTIALS_FULL_URI is not a URL")
		}
		hosts = append(hosts, h)
	}
	hc, err := safety.NewEndpointClientPolicy(hosts, safety.HTTPOptions{UserAgent: ua}, safety.EndpointPolicy{AllowMetadata: true})
	if err != nil {
		return nil, err
	}
	if p.containerURL != "" {
		return endpointcreds.New(p.containerURL, func(o *endpointcreds.Options) {
			o.HTTPClient = hc
			o.AuthorizationToken = os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
		}), nil
	}
	return ec2rolecreds.New(func(o *ec2rolecreds.Options) {
		o.Client = imds.New(imds.Options{HTTPClient: hc})
	}), nil
}

// DescribeCredentialSource reports which credential source a scan of
// aws://<profile> would use, reading env and files only (doctor).
func DescribeCredentialSource(ctx context.Context, profile string, instanceCredentials bool) (string, error) {
	p, err := planCredentials(ctx, profile, chainOptions{instanceCredentials: instanceCredentials})
	if err != nil {
		return "", err
	}
	return p.Describe(), nil
}
