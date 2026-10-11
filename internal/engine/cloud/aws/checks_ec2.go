package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/iamstoick/scnr/internal/domain"
)

const (
	portSSH = 22
	portRDP = 3389
)

// checkEC2: security groups open to the world, default security groups
// with rules, unencrypted EBS volumes, EBS default encryption, instances
// allowing IMDSv1. Reads ids, protocols, ports, CIDRs and flags only (no
// tags, descriptions or user data).
func checkEC2(ctx context.Context, r *run, cl *clients) error {
	if err := checkSecurityGroups(ctx, r, cl); err != nil {
		return err
	}
	if err := checkVolumes(ctx, r, cl); err != nil {
		return err
	}
	if err := checkInstances(ctx, r, cl); err != nil {
		return err
	}
	def, err := cl.ec2.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
	if err != nil {
		return err
	}
	if !aws.ToBool(def.EbsEncryptionByDefault) {
		return r.finding(RuleEBSDefaultEncryption, fmt.Sprintf("arn:aws:ec2:%s:%s:ebs-encryption-by-default", cl.region, r.account), domain.Confirmed, "EbsEncryptionByDefault=false")
	}
	return nil
}

func (r *run) ec2ARN(region, kind, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:%s/%s", region, r.account, kind, id)
}

func checkSecurityGroups(ctx context.Context, r *run, cl *clients) error {
	pager := ec2.NewDescribeSecurityGroupsPaginator(cl.ec2, &ec2.DescribeSecurityGroupsInput{})
	return pages(ctx, r.cov, "ec2:DescribeSecurityGroups", cl.region, pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, sg := range page.SecurityGroups {
			if err := checkSecurityGroup(r, cl.region, sg); err != nil {
				return 0, err
			}
		}
		return len(page.SecurityGroups), nil
	})
}

// worldOpen reports whether the permission admits any address.
func worldOpen(p types.IpPermission) bool {
	for _, rg := range p.IpRanges {
		if aws.ToString(rg.CidrIp) == "0.0.0.0/0" {
			return true
		}
	}
	for _, rg := range p.Ipv6Ranges {
		if aws.ToString(rg.CidrIpv6) == "::/0" {
			return true
		}
	}
	return false
}

// coversPort reports whether a TCP permission includes port.
func coversPort(p types.IpPermission, port int32) bool {
	proto := aws.ToString(p.IpProtocol)
	if proto != "tcp" && proto != "6" {
		return false
	}
	from, to := aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort)
	return from <= port && port <= to
}

func checkSecurityGroup(r *run, region string, sg types.SecurityGroup) error {
	id := aws.ToString(sg.GroupId)
	if id == "" {
		return nil
	}
	arn := r.ec2ARN(region, "security-group", id)
	if aws.ToString(sg.GroupName) == "default" && len(sg.IpPermissions) > 0 {
		if err := r.finding(RuleDefaultSGAllowsTraffic, arn, domain.Confirmed, fmt.Sprintf("default security group of %s has %d ingress rule(s)", aws.ToString(sg.VpcId), len(sg.IpPermissions))); err != nil {
			return err
		}
	}
	// One finding per rule per group, whichever permission triggered it.
	seen := map[string]bool{}
	emit := func(rule, what string) error {
		if seen[rule] {
			return nil
		}
		seen[rule] = true
		return r.finding(rule, arn, domain.Confirmed, what)
	}
	for _, p := range sg.IpPermissions {
		if !worldOpen(p) {
			continue
		}
		if aws.ToString(p.IpProtocol) == "-1" {
			if err := emit(RuleSGOpenAll, "all protocols and ports open to 0.0.0.0/0 or ::/0"); err != nil {
				return err
			}
			continue
		}
		ports := fmt.Sprintf("tcp %d-%d", aws.ToInt32(p.FromPort), aws.ToInt32(p.ToPort))
		if coversPort(p, portSSH) {
			if err := emit(RuleSGOpenSSH, ports+" (SSH) open to 0.0.0.0/0 or ::/0"); err != nil {
				return err
			}
		}
		if coversPort(p, portRDP) {
			if err := emit(RuleSGOpenRDP, ports+" (RDP) open to 0.0.0.0/0 or ::/0"); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkVolumes(ctx context.Context, r *run, cl *clients) error {
	pager := ec2.NewDescribeVolumesPaginator(cl.ec2, &ec2.DescribeVolumesInput{})
	return pages(ctx, r.cov, "ec2:DescribeVolumes", cl.region, pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, v := range page.Volumes {
			id := aws.ToString(v.VolumeId)
			if id == "" || aws.ToBool(v.Encrypted) {
				continue
			}
			if err := r.finding(RuleEBSVolumeUnencrypted, r.ec2ARN(cl.region, "volume", id), domain.Confirmed, fmt.Sprintf("Encrypted=false State=%s", v.State)); err != nil {
				return 0, err
			}
		}
		return len(page.Volumes), nil
	})
}

func checkInstances(ctx context.Context, r *run, cl *clients) error {
	pager := ec2.NewDescribeInstancesPaginator(cl.ec2, &ec2.DescribeInstancesInput{})
	return pages(ctx, r.cov, "ec2:DescribeInstances", cl.region, pager.HasMorePages, func(ctx context.Context) (int, error) {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				n++
				id := aws.ToString(inst.InstanceId)
				if id == "" || inst.MetadataOptions == nil || inst.MetadataOptions.HttpTokens != types.HttpTokensStateOptional {
					continue
				}
				if inst.State != nil && inst.State.Name == types.InstanceStateNameTerminated {
					continue
				}
				if err := r.finding(RuleIMDSv1Allowed, r.ec2ARN(cl.region, "instance", id), domain.Confirmed, "MetadataOptions.HttpTokens=optional"); err != nil {
					return 0, err
				}
			}
		}
		return n, nil
	})
}
