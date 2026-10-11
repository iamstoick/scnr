// Package awstest is an httptest fake of the AWS APIs the cloud-aws engine
// calls (query/XML for STS, IAM, EC2, RDS; REST/XML for S3; JSON 1.1 for
// CloudTrail and KMS). Responses carry a canary string in every field the
// engine must never copy (tags, descriptions, master usernames, bucket
// names of trails) so tests can assert it appears nowhere. Tests never
// touch the real AWS.
package awstest

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Canary is the string planted in forbidden fields.
const Canary = "CANARY-SECRET-7f3a9c-DO-NOT-COPY"

// DefaultAccount is the fixture's account id.
const DefaultAccount = "123456789012"

// Fixture tunes the fake account.
type Fixture struct {
	Account string
	// Principal is the GetCallerIdentity ARN; defaults to an IAM user.
	Principal string
	// Regions returned by DescribeRegions; default us-east-1 and eu-west-1.
	Regions []string
	// SecurityGroupPages > 1 makes DescribeSecurityGroups paginate that
	// many pages (one group per page) to exercise the pagination cap.
	SecurityGroupPages int
	// WeakPasswordPolicy returns a weak policy instead of NoSuchEntity.
	WeakPasswordPolicy bool
	// NoTrails makes DescribeTrails return an empty list.
	NoTrails bool
	// AssumeRole makes STS answer AssumeRole with fixed session keys
	// (returned session key id is "ASIAFAKEASSUMEDROLE1").
	AssumeRole bool
}

// Request is one recorded API call.
type Request struct {
	Service string
	Op      string
	Path    string
}

// Server is the fake.
type Server struct {
	*httptest.Server
	mu       sync.Mutex
	fixture  Fixture
	requests []Request
}

// New starts the fake; it is closed when the test ends.
func New(t testing.TB, f Fixture) *Server {
	t.Helper()
	if f.Account == "" {
		f.Account = DefaultAccount
	}
	if f.Principal == "" {
		f.Principal = "arn:aws:iam::" + f.Account + ":user/audit"
	}
	if len(f.Regions) == 0 {
		f.Regions = []string{"us-east-1", "eu-west-1"}
	}
	s := &Server{fixture: f}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.Close)
	return s
}

// Host returns the loopback host the SDK must be allowed to reach.
func (s *Server) Host() string {
	u := strings.TrimPrefix(s.URL, "http://")
	return u[:strings.LastIndex(u, ":")]
}

// SetAccount changes the account GetCallerIdentity reports (identity
// change mid-run).
func (s *Server) SetAccount(a string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fixture.Account = a
	s.fixture.Principal = "arn:aws:iam::" + a + ":user/audit"
}

// Requests returns every recorded call.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// Count returns how many calls of op were received.
func (s *Server) Count(op string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Op == op {
			n++
		}
	}
	return n
}

var credRe = regexp.MustCompile(`Credential=[^/]+/\d{8}/[a-z0-9-]+/([a-z0-9-]+)/aws4_request`)

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	service := ""
	if m := credRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		service = m[1]
	}
	op := ""
	switch {
	case r.Header.Get("X-Amz-Target") != "":
		tgt := r.Header.Get("X-Amz-Target")
		op = tgt[strings.LastIndex(tgt, ".")+1:]
	case service == "s3" || (service == "" && r.Header.Get("X-Amz-Target") == "" && !strings.Contains(string(body), "Action=")):
		service = "s3"
		op = s3Op(r)
	default:
		vals, _ := parseForm(body)
		op = vals["Action"]
		if service == "" {
			service = serviceForVersion(vals["Version"])
		}
	}
	s.mu.Lock()
	s.requests = append(s.requests, Request{Service: service, Op: op, Path: r.URL.RequestURI()})
	f := s.fixture
	s.mu.Unlock()

	switch service {
	case "sts":
		s.sts(w, f, op)
	case "iam":
		s.iam(w, f, op, mustForm(body))
	case "ec2":
		s.ec2(w, f, op, mustForm(body))
	case "rds":
		s.rds(w, f, op)
	case "s3":
		s.s3(w, f, op, r)
	case "cloudtrail":
		s.cloudtrail(w, f, op)
	case "kms":
		s.kms(w, f, op, body)
	default:
		http.Error(w, "unknown service "+service, http.StatusBadRequest)
	}
}

func parseForm(body []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range strings.Split(string(body), "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if uv, err := urlUnescape(v); err == nil {
			v = uv
		}
		out[k] = v
	}
	return out, nil
}

func mustForm(body []byte) map[string]string {
	m, _ := parseForm(body)
	return m
}

func urlUnescape(s string) (string, error) {
	s = strings.ReplaceAll(s, "+", " ")
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			n, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", err
			}
			b.WriteByte(byte(n))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String(), nil
}

func serviceForVersion(v string) string {
	switch v {
	case "2011-06-15":
		return "sts"
	case "2010-05-08":
		return "iam"
	case "2016-11-15":
		return "ec2"
	case "2014-10-31":
		return "rds"
	}
	return ""
}

func s3Op(r *http.Request) string {
	q := r.URL.Query()
	bucket := strings.Trim(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && bucket == "":
		return "ListBuckets"
	case r.Method == http.MethodPut && q.Has("policy"):
		return "PutBucketPolicy"
	case r.Method == http.MethodGet && q.Has("policyStatus"):
		return "GetBucketPolicyStatus"
	case r.Method == http.MethodGet && q.Has("acl"):
		return "GetBucketAcl"
	case r.Method == http.MethodGet && q.Has("publicAccessBlock"):
		return "GetPublicAccessBlock"
	case r.Method == http.MethodGet && q.Has("encryption"):
		return "GetBucketEncryption"
	case r.Method == http.MethodGet && q.Has("logging"):
		return "GetBucketLogging"
	case r.Method == http.MethodGet && q.Has("location"):
		return "GetBucketLocation"
	}
	return r.Method + " " + r.URL.Path
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// queryResponse wraps an awsquery result (IAM, STS, RDS).
func queryResponse(w http.ResponseWriter, op, ns, result string) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<%sResponse xmlns="%s"><%sResult>%s</%sResult><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></%sResponse>`, op, ns, op, result, op, op)
}

func queryError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error><RequestId>req-1</RequestId></ErrorResponse>`, code, esc(msg))
}

func (s *Server) sts(w http.ResponseWriter, f Fixture, op string) {
	const ns = "https://sts.amazonaws.com/doc/2011-06-15/"
	switch op {
	case "GetCallerIdentity":
		queryResponse(w, op, ns, fmt.Sprintf(`<Arn>%s</Arn><UserId>AIDAFAKEUSERID000001</UserId><Account>%s</Account>`, esc(f.Principal), f.Account))
	case "AssumeRole":
		if !f.AssumeRole {
			queryError(w, 403, "AccessDenied", "not authorized")
			return
		}
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		queryResponse(w, op, ns, fmt.Sprintf(`<Credentials><AccessKeyId>ASIAFAKEASSUMEDROLE1</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>FQoGZXIvYXdzEFAKE</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::%s:assumed-role/audit/scnr</Arn><AssumedRoleId>AROAFAKE:scnr</AssumedRoleId></AssumedRoleUser>`,
			strings.Repeat("s", 40), exp, f.Account))
	default:
		queryError(w, 400, "InvalidAction", op)
	}
}

func (s *Server) iam(w http.ResponseWriter, f Fixture, op string, form map[string]string) {
	const ns = "https://iam.amazonaws.com/doc/2010-05-08/"
	old := time.Now().Add(-200 * 24 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().Add(-5 * 24 * time.Hour).UTC().Format(time.RFC3339)
	switch op {
	case "GetAccountSummary":
		queryResponse(w, op, ns, `<SummaryMap><entry><key>AccountMFAEnabled</key><value>0</value></entry><entry><key>AccountAccessKeysPresent</key><value>1</value></entry><entry><key>Users</key><value>2</value></entry></SummaryMap>`)
	case "GetAccountPasswordPolicy":
		if f.WeakPasswordPolicy {
			queryResponse(w, op, ns, `<PasswordPolicy><MinimumPasswordLength>8</MinimumPasswordLength><RequireSymbols>false</RequireSymbols><RequireNumbers>true</RequireNumbers><RequireUppercaseCharacters>true</RequireUppercaseCharacters><RequireLowercaseCharacters>true</RequireLowercaseCharacters><AllowUsersToChangePassword>true</AllowUsersToChangePassword><ExpirePasswords>false</ExpirePasswords></PasswordPolicy>`)
			return
		}
		queryError(w, 404, "NoSuchEntity", "The Password Policy with domain name "+f.Account+" cannot be found.")
	case "ListUsers":
		queryResponse(w, op, ns, fmt.Sprintf(`<Users><member><Path>/</Path><UserName>alice</UserName><UserId>AIDAALICE</UserId><Arn>arn:aws:iam::%[1]s:user/alice</Arn><CreateDate>%[2]s</CreateDate><Tags><member><Key>owner</Key><Value>%[3]s</Value></member></Tags></member><member><Path>/</Path><UserName>bob</UserName><UserId>AIDABOB</UserId><Arn>arn:aws:iam::%[1]s:user/bob</Arn><CreateDate>%[2]s</CreateDate></member></Users><IsTruncated>false</IsTruncated>`, f.Account, old, Canary))
	case "GetLoginProfile":
		if form["UserName"] == "alice" {
			queryResponse(w, op, ns, fmt.Sprintf(`<LoginProfile><UserName>alice</UserName><CreateDate>%s</CreateDate><PasswordResetRequired>false</PasswordResetRequired></LoginProfile>`, old))
			return
		}
		queryError(w, 404, "NoSuchEntity", "Login Profile for User "+form["UserName"]+" cannot be found.")
	case "ListMFADevices":
		queryResponse(w, op, ns, `<MFADevices/><IsTruncated>false</IsTruncated>`)
	case "ListAccessKeys":
		date := fresh
		if form["UserName"] == "alice" {
			date = old
		}
		queryResponse(w, op, ns, fmt.Sprintf(`<AccessKeyMetadata><member><UserName>%s</UserName><AccessKeyId>AKIAFAKEKEY%s</AccessKeyId><Status>Active</Status><CreateDate>%s</CreateDate></member></AccessKeyMetadata><IsTruncated>false</IsTruncated>`, form["UserName"], strings.ToUpper(form["UserName"]), date))
	default:
		queryError(w, 400, "InvalidAction", op)
	}
}

func ec2Response(w http.ResponseWriter, op, body string) {
	w.Header().Set("Content-Type", "text/xml")
	fmt.Fprintf(w, `<%sResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>req-1</requestId>%s</%sResponse>`, op, body, op)
}

func tagSet() string {
	return fmt.Sprintf(`<tagSet><item><key>Name</key><value>%s</value></item></tagSet>`, Canary)
}

func (s *Server) ec2(w http.ResponseWriter, f Fixture, op string, form map[string]string) {
	switch op {
	case "DescribeRegions":
		var b strings.Builder
		for _, r := range f.Regions {
			fmt.Fprintf(&b, `<item><regionName>%s</regionName><regionEndpoint>ec2.%s.amazonaws.com</regionEndpoint><optInStatus>opt-in-not-required</optInStatus></item>`, r, r)
		}
		ec2Response(w, op, "<regionInfo>"+b.String()+"</regionInfo>")
	case "DescribeSecurityGroups":
		if f.SecurityGroupPages > 1 {
			page := 1
			if t := form["NextToken"]; t != "" {
				page, _ = strconv.Atoi(strings.TrimPrefix(t, "page-"))
			}
			next := ""
			if page < f.SecurityGroupPages {
				next = fmt.Sprintf("<nextToken>page-%d</nextToken>", page+1)
			}
			ec2Response(w, op, fmt.Sprintf(`<securityGroupInfo><item><groupId>sg-%06d</groupId><groupName>paged-%d</groupName><groupDescription>%s</groupDescription><vpcId>vpc-1</vpcId><ownerId>%s</ownerId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions>%s</item></securityGroupInfo>%s`, page, page, Canary, f.Account, tagSet(), next))
			return
		}
		ec2Response(w, op, fmt.Sprintf(`<securityGroupInfo>
<item><groupId>sg-0open0000000001</groupId><groupName>web-open</groupName><groupDescription>%[1]s</groupDescription><vpcId>vpc-1</vpcId><ownerId>%[2]s</ownerId><ipPermissions>
<item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp><description>%[1]s</description></item></ipRanges><ipv6Ranges/></item>
<item><ipProtocol>tcp</ipProtocol><fromPort>3389</fromPort><toPort>3389</toPort><ipRanges/><ipv6Ranges><item><cidrIpv6>::/0</cidrIpv6></item></ipv6Ranges></item>
<item><ipProtocol>-1</ipProtocol><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>
<item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item>
</ipPermissions>%[3]s</item>
<item><groupId>sg-0default000000002</groupId><groupName>default</groupName><groupDescription>default VPC security group</groupDescription><vpcId>vpc-1</vpcId><ownerId>%[2]s</ownerId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>80</fromPort><toPort>80</toPort><ipRanges><item><cidrIp>10.0.0.0/8</cidrIp></item></ipRanges></item></ipPermissions>%[3]s</item>
<item><groupId>sg-0clean00000000003</groupId><groupName>clean</groupName><groupDescription>ok</groupDescription><vpcId>vpc-1</vpcId><ownerId>%[2]s</ownerId><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>10.1.0.0/16</cidrIp></item></ipRanges></item></ipPermissions></item>
</securityGroupInfo>`, Canary, f.Account, tagSet()))
	case "DescribeVolumes":
		ec2Response(w, op, fmt.Sprintf(`<volumeSet><item><volumeId>vol-0plain0000000001</volumeId><size>8</size><encrypted>false</encrypted><status>in-use</status>%[1]s</item><item><volumeId>vol-0enc000000000002</volumeId><size>8</size><encrypted>true</encrypted><status>in-use</status>%[1]s</item></volumeSet>`, tagSet()))
	case "DescribeInstances":
		ec2Response(w, op, fmt.Sprintf(`<reservationSet><item><reservationId>r-1</reservationId><ownerId>%[1]s</ownerId><instancesSet>
<item><instanceId>i-0v1000000000000001</instanceId><instanceState><code>16</code><name>running</name></instanceState><metadataOptions><state>applied</state><httpTokens>optional</httpTokens><httpEndpoint>enabled</httpEndpoint></metadataOptions>%[2]s</item>
<item><instanceId>i-0v2000000000000002</instanceId><instanceState><code>16</code><name>running</name></instanceState><metadataOptions><state>applied</state><httpTokens>required</httpTokens><httpEndpoint>enabled</httpEndpoint></metadataOptions>%[2]s</item>
</instancesSet></item></reservationSet>`, f.Account, tagSet()))
	case "GetEbsEncryptionByDefault":
		ec2Response(w, op, `<ebsEncryptionByDefault>false</ebsEncryptionByDefault>`)
	default:
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(400)
		fmt.Fprintf(w, `<Response><Errors><Error><Code>InvalidAction</Code><Message>%s</Message></Error></Errors><RequestID>req-1</RequestID></Response>`, esc(op))
	}
}

func (s *Server) rds(w http.ResponseWriter, f Fixture, op string) {
	const ns = "http://rds.amazonaws.com/doc/2014-10-31/"
	switch op {
	case "DescribeDBInstances":
		queryResponse(w, op, ns, fmt.Sprintf(`<DBInstances><DBInstance><DBInstanceIdentifier>db-public</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:%[1]s:db:db-public</DBInstanceArn><Engine>postgres</Engine><MasterUsername>%[2]s</MasterUsername><PubliclyAccessible>true</PubliclyAccessible><StorageEncrypted>false</StorageEncrypted><BackupRetentionPeriod>0</BackupRetentionPeriod><TagList><Tag><Key>team</Key><Value>%[2]s</Value></Tag></TagList></DBInstance><DBInstance><DBInstanceIdentifier>db-ok</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:%[1]s:db:db-ok</DBInstanceArn><Engine>postgres</Engine><MasterUsername>%[2]s</MasterUsername><PubliclyAccessible>false</PubliclyAccessible><StorageEncrypted>true</StorageEncrypted><BackupRetentionPeriod>7</BackupRetentionPeriod></DBInstance></DBInstances>`, f.Account, Canary))
	default:
		queryError(w, 400, "InvalidAction", op)
	}
}

func s3Error(w http.ResponseWriter, status int, code, bucket string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><BucketName>%s</BucketName><RequestId>req-1</RequestId><HostId>h</HostId></Error>`, code, code, esc(bucket))
}

func (s *Server) s3(w http.ResponseWriter, f Fixture, op string, r *http.Request) {
	bucket := strings.Trim(r.URL.Path, "/")
	public := bucket == "public-data"
	w.Header().Set("Content-Type", "application/xml")
	switch op {
	case "ListBuckets":
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>owner1</ID><DisplayName>%s</DisplayName></Owner><Buckets><Bucket><Name>public-data</Name><CreationDate>2020-01-01T00:00:00.000Z</CreationDate></Bucket><Bucket><Name>private-logs</Name><CreationDate>2020-01-01T00:00:00.000Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>`, Canary)
	case "GetBucketPolicyStatus":
		if !public {
			s3Error(w, 404, "NoSuchBucketPolicy", bucket)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><PolicyStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsPublic>true</IsPublic></PolicyStatus>`)
	case "GetBucketAcl":
		grants := `<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>owner1</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>`
		if public {
			grants += `<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>`
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>owner1</ID><DisplayName>%s</DisplayName></Owner><AccessControlList>%s</AccessControlList></AccessControlPolicy>`, Canary, grants)
	case "GetPublicAccessBlock":
		if public {
			s3Error(w, 404, "NoSuchPublicAccessBlockConfiguration", bucket)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
	case "GetBucketEncryption":
		if public {
			s3Error(w, 404, "ServerSideEncryptionConfigurationNotFoundError", bucket)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`)
	case "GetBucketLogging":
		if public {
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
			return
		}
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LoggingEnabled><TargetBucket>private-logs</TargetBucket><TargetPrefix>log/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`)
	default:
		s3Error(w, 405, "MethodNotAllowed", bucket)
	}
}

func jsonResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) cloudtrail(w http.ResponseWriter, f Fixture, op string) {
	switch op {
	case "DescribeTrails":
		if f.NoTrails {
			jsonResponse(w, map[string]any{"trailList": []any{}})
			return
		}
		jsonResponse(w, map[string]any{"trailList": []map[string]any{{
			"Name": "main", "TrailARN": "arn:aws:cloudtrail:us-east-1:" + f.Account + ":trail/main", "HomeRegion": "us-east-1",
			"IsMultiRegionTrail": false, "LogFileValidationEnabled": false, "S3BucketName": Canary, "S3KeyPrefix": Canary,
		}}})
	case "GetTrailStatus":
		jsonResponse(w, map[string]any{"IsLogging": false})
	default:
		w.WriteHeader(400)
		jsonResponse(w, map[string]any{"__type": "InvalidAction", "message": op})
	}
}

func (s *Server) kms(w http.ResponseWriter, f Fixture, op string, body []byte) {
	arn := "arn:aws:kms:us-east-1:" + f.Account + ":key/11111111-2222-3333-4444-555555555555"
	switch op {
	case "ListKeys":
		jsonResponse(w, map[string]any{"Keys": []map[string]any{{"KeyId": "11111111-2222-3333-4444-555555555555", "KeyArn": arn}}, "Truncated": false})
	case "DescribeKey":
		jsonResponse(w, map[string]any{"KeyMetadata": map[string]any{
			"AWSAccountId": f.Account, "KeyId": "11111111-2222-3333-4444-555555555555", "Arn": arn, "Description": Canary,
			"KeyManager": "CUSTOMER", "KeyState": "Enabled", "KeySpec": "SYMMETRIC_DEFAULT", "Origin": "AWS_KMS", "Enabled": true, "KeyUsage": "ENCRYPT_DECRYPT",
		}})
	case "GetKeyRotationStatus":
		jsonResponse(w, map[string]any{"KeyRotationEnabled": false})
	default:
		w.WriteHeader(400)
		jsonResponse(w, map[string]any{"__type": "InvalidAction", "message": op + string(body)})
	}
}
