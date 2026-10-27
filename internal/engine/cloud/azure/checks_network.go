package azure

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// nsgRule is the subset of a security rule the checks read: direction,
// verdict, ports and sources. Default rules are skipped (they deny).
type nsgRule struct {
	Name       string `json:"name"`
	Properties struct {
		Access                string   `json:"access"`
		Direction             string   `json:"direction"`
		DestinationPortRange  string   `json:"destinationPortRange"`
		DestinationPortRanges []string `json:"destinationPortRanges"`
		SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
		SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
		Protocol              string   `json:"protocol"`
	} `json:"properties"`
}

type nsg struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		SecurityRules []nsgRule `json:"securityRules"`
	} `json:"properties"`
}

func openToInternet(rule nsgRule, ports ...string) bool {
	p := rule.Properties
	if !strings.EqualFold(p.Access, "Allow") || !strings.EqualFold(p.Direction, "Inbound") {
		return false
	}
	addrs := append([]string{p.SourceAddressPrefix}, p.SourceAddressPrefixes...)
	open := false
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a == "*" || a == "0.0.0.0" || a == "0.0.0.0/0" || a == "Internet" || a == "Any" {
			open = true
		}
	}
	if !open {
		return false
	}
	ranges := append([]string{p.DestinationPortRange}, p.DestinationPortRanges...)
	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if r == "*" {
			return true
		}
		if lo, hi, ok := strings.Cut(r, "-"); ok {
			loN, loErr := strconv.Atoi(strings.TrimSpace(lo))
			hiN, hiErr := strconv.Atoi(strings.TrimSpace(hi))
			if loErr != nil || hiErr != nil {
				continue
			}
			for _, want := range ports {
				wantN, err := strconv.Atoi(want)
				if err == nil && loN <= wantN && wantN <= hiN {
					return true
				}
			}
			continue
		}
		for _, want := range ports {
			if r == want {
				return true
			}
		}
	}
	return false
}

func checkNSGPorts(ctx context.Context, r *run, ruleID, title string, ports ...string) error {
	return armList(ctx, r.s, "/subscriptions/"+r.sub+"/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01",
		func(page []nsg) error {
			for _, g := range page {
				for _, rule := range g.Properties.SecurityRules {
					if openToInternet(rule, ports...) {
						return r.finding(ruleID, rule.Name+"@"+g.ID,
							fmt.Sprintf("NSG %q rule %q: %s open to the internet (%s)", g.Name, rule.Name, title, ports))
					}
				}
			}
			return nil
		})
}

// checkNSGOpenRDP flags RDP reachable from the internet: the first thing
// password-guessing botnets try.
func checkNSGOpenRDP(ctx context.Context, r *run) error {
	return checkNSGPorts(ctx, r, "cloud.azure.nsg.open-rdp", "RDP/3389", "3389")
}

// checkNSGOpenSSH flags SSH reachable from the internet.
func checkNSGOpenSSH(ctx context.Context, r *run) error {
	return checkNSGPorts(ctx, r, "cloud.azure.nsg.open-ssh", "SSH/22", "22")
}
