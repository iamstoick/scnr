// Package nmap drives the nmap binary for service/version detection and
// parses its XML output. It never enables NSE scripts, UDP or OS detection
// (SAFETY.md item 10) and scans only the addresses the gate pinned.
package nmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/adapter"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/engine/netscan"
	"github.com/gerald/scnr/internal/safety"
)

// Name of the engine.
const Name = "adapter:nmap"

// MinVersion we have fixtures for.
const MinVersion = "7.80"

const maxPortsArg = 4096

// Adapter implements adapter.Adapter. Binary, MinVersion, Version and
// Detect come from the embedded Base.
type Adapter struct {
	adapter.Base
	rules engine.RuleSet
}

// New builds the adapter, borrowing the net.* rule prose from netscan.
func New() (*Adapter, error) {
	ns, err := netscan.New()
	if err != nil {
		return nil, err
	}
	return &Adapter{Base: adapter.Base{BinaryName: "nmap", Min: MinVersion}, rules: ns.Rules()}, nil
}

// Name implements engine.Engine.
func (a *Adapter) Name() string { return Name }

// Supports hosts, ranges and the host behind a URL.
func (a *Adapter) Supports(t domain.Target) bool {
	switch t.Type {
	case domain.TargetHost, domain.TargetCIDR, domain.TargetURL:
		return true
	}
	return false
}

// Plan implements engine.Engine.
func (a *Adapter) Plan(ctx context.Context, t domain.Target, o engine.Options) (engine.Plan, error) {
	return a.PlanTool(ctx, a, t, o, "service detection (TCP connect, no scripts)", 2*time.Minute)
}

// targets returns the argv entries naming what to scan: the gate-pinned
// addresses for a hostname (never the name itself, so nmap cannot be sent
// elsewhere by a changed DNS answer), the IP literal, or the CIDR.
func targets(t domain.Target, o engine.Options) ([]string, error) {
	switch t.Type {
	case domain.TargetCIDR:
		if _, err := netip.ParsePrefix(t.Value); err != nil {
			return nil, err
		}
		return []string{t.Value}, nil
	case domain.TargetHost, domain.TargetURL:
		host := t.Hostname
		if host == "" {
			host = t.Value
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			return []string{ip.String()}, nil
		}
		if o.Dialer != nil {
			if pinned := o.Dialer.Pinned(host); len(pinned) > 0 {
				out := make([]string, len(pinned))
				for i, p := range pinned {
					out[i] = p.String()
				}
				return out, nil
			}
		}
		return nil, fmt.Errorf("nmap: hostname %q has no pinned addresses from the safety gate", host)
	}
	return nil, fmt.Errorf("nmap: unsupported target type %s", t.Type)
}

// Args builds the argument array. Only read-only, connect-based options are
// used; rate and parallelism come from the shared Limits so the adapter
// stays under the same caps as native engines.
func (a *Adapter) Args(t domain.Target, o engine.Options) ([]string, error) {
	tgts, err := targets(t, o)
	if err != nil {
		return nil, err
	}
	rate, par := 100, 16
	if o.Limiter != nil {
		rate, par = o.Limiter.RatePerSec, o.Limiter.PerHostConcurrency
	}
	args := []string{"-sT", "-sV", "-Pn", "-n", "-T3", "-oX", "-", "--max-rate", strconv.Itoa(rate), "--max-parallelism", strconv.Itoa(par), "--host-timeout", "10m"}
	switch {
	case len(o.Ports) > 0:
		if len(o.Ports) > maxPortsArg {
			args = append(args, "-p-")
		} else {
			parts := make([]string, len(o.Ports))
			for i, p := range o.Ports {
				parts[i] = strconv.Itoa(p)
			}
			args = append(args, "-p", strings.Join(parts, ","))
		}
	case o.Profile.Name == "deep":
		args = append(args, "-p-")
	case o.Profile.Ports == "top100":
		args = append(args, "--top-ports", "100")
	default:
		args = append(args, "--top-ports", "1000")
	}
	if o.Scope != nil {
		if deny := o.Scope.DenyAddresses(); len(deny) > 0 {
			args = append(args, "--exclude", strings.Join(deny, ","))
		}
	}
	for _, tg := range tgts {
		if err := adapter.FlagSafeValue(tg); err != nil {
			return nil, err
		}
	}
	return append(args, tgts...), nil
}

// Run implements engine.Engine. Exposure findings on private targets are
// downgraded to medium exactly as the native scanner does, so both engines
// agree on the same fingerprint.
func (a *Adapter) Run(ctx context.Context, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	return a.RunTool(ctx, a, t, o, func(f domain.Finding) error {
		if !t.Public && (f.RuleID == "net.exposed-admin-port" || f.RuleID == "net.exposed-db-port") {
			f.Severity = domain.Medium
		}
		return emit(f)
	}, "")
}

// nmaprun is the subset of nmap's XML we read (field allowlist).
type nmaprun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   int    `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name      string `xml:"name,attr"`
					Product   string `xml:"product,attr"`
					Version   string `xml:"version,attr"`
					ExtraInfo string `xml:"extrainfo,attr"`
					Tunnel    string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// Parse reads nmap XML (strict decoder, no external entities: encoding/xml
// never fetches them) and emits net.open-port plus exposure findings.
func (a *Adapter) Parse(r io.Reader, emit func(domain.Finding) error) error {
	dec := xml.NewDecoder(r)
	dec.Strict = true
	dec.Entity = nil // undefined entities are errors, not expansions
	var run nmaprun
	if err := dec.Decode(&run); err != nil {
		return fmt.Errorf("nmap xml: %w", err)
	}
	red := safety.NewRedactor()
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		var host string
		for _, ad := range h.Addresses {
			if ad.Type == "ipv4" || ad.Type == "ipv6" {
				if ip, err := netip.ParseAddr(ad.Addr); err == nil {
					host = ip.String()
					break
				}
			}
		}
		if host == "" {
			continue
		}
		assetKey := "host:" + host
		for _, p := range h.Ports.Ports {
			if p.Protocol != "tcp" || p.State.State != "open" || p.PortID < 1 || p.PortID > 65535 {
				continue
			}
			loc := net.JoinHostPort(host, strconv.Itoa(p.PortID))
			svc := strings.TrimSpace(strings.Join(nonEmpty(p.Service.Name, p.Service.Product, p.Service.Version, p.Service.ExtraInfo), " "))
			svc = safety.StripControl(svc)
			if len(svc) > 200 {
				svc = svc[:200]
			}
			ev := []domain.Evidence{red.TextEvidence("tool_output", loc, "nmap -sV: "+svc)}
			f := a.rules.NewFinding("net.open-port", assetKey, loc, domain.Confirmed)
			if svc != "" {
				f.Title = fmt.Sprintf("Open TCP port %d (%s)", p.PortID, svc)
			} else {
				f.Title = fmt.Sprintf("Open TCP port %d", p.PortID)
			}
			f.Evidence = ev
			if err := emit(f); err != nil {
				return err
			}
			if rule, name, ok := netscan.Classify(p.PortID); ok {
				g := a.rules.NewFinding(rule, assetKey, loc, domain.Firm)
				g.Title = fmt.Sprintf("%s (%s on %d)", g.Title, name, p.PortID)
				g.Evidence = ev
				if err := emit(g); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

var _ adapter.Adapter = (*Adapter)(nil)
