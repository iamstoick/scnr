// Package wizard is the interactive front door. It only produces a
// ScanRequest; the cli package executes it. Nothing here touches the
// network or the store.
package wizard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/iamstoick/scnr/internal/config"
	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/engine"
	"github.com/iamstoick/scnr/internal/target"
)

// ScanRequest is everything `scnr scan` needs; every field maps to a flag.
type ScanRequest struct {
	Targets        []string
	Type           string
	Profile        string
	Engines        []string
	SkipEngines    []string
	Out            string
	Formats        string
	ScopePath      string
	NonInteractive bool
	Offline        bool
	MaxHosts       int
	Ports          string
	Rate           int
	Concurrency    int
	Strict         bool
	AckAuthorized  bool
	AuditFile      string
	AllowRaise     bool
	DBPath         string
	// Phase 2: vulnerability-management options.
	Policy    string // --policy policy.yaml
	Baseline  string // --baseline baseline.yaml
	Diff      string // --diff latest|SCAN-ID
	Templates string // --templates DIR
	// Schedule names the schedule running this scan. Set by the daemon
	// only; it is recorded on scans.meta and never comes from a flag.
	Schedule string
}

// Flags renders the request as a reproducible command line.
func (r ScanRequest) Flags() string {
	parts := []string{"scnr scan"}
	parts = append(parts, r.Targets...)
	if r.Type != "" {
		parts = append(parts, "--type", r.Type)
	}
	if r.Profile != "" {
		parts = append(parts, "--profile", r.Profile)
	}
	if r.Out != "" {
		parts = append(parts, "--out", r.Out)
	}
	if r.Formats != "" {
		parts = append(parts, "--format", r.Formats)
	}
	if r.Offline {
		parts = append(parts, "--offline")
	}
	if r.Ports != "" {
		parts = append(parts, "--ports", r.Ports)
	}
	if r.AckAuthorized {
		parts = append(parts, "--ack-authorized")
	}
	parts = append(parts, "--non-interactive")
	return strings.Join(parts, " ")
}

// Deps are the callbacks the wizard needs from the cli.
type Deps struct {
	Detect func(ctx context.Context, raw string) (domain.Target, error)
	// Plan returns a human summary per engine for a target and profile.
	Plan func(ctx context.Context, t domain.Target, profile string) ([]string, error)
	// SCAApplies reports whether the online disclosure is relevant.
	SCAApplies func(t domain.Target) bool
	// Acknowledged is true when scnr.yaml already records the ack.
	Acknowledged bool
	Out          io.Writer
}

// ErrCancelled is returned when the user aborts.
var ErrCancelled = errors.New("wizard cancelled")

// Run walks the user through the steps and returns a request.
func Run(ctx context.Context, d Deps) (ScanRequest, error) {
	req := ScanRequest{Formats: "html,json", Profile: "standard"}
	var raw string
	var t domain.Target

	// Step 1: target.
	for {
		if err := huh.NewForm(huh.NewGroup(
			huh.NewInput().Title("What do you want to check?").
				Description("A URL (https://example.com), a host or IP, a network range (10.0.0.0/24), or a path to code (.)").
				Value(&raw).Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("enter a target")
				}
				return nil
			}),
		)).RunWithContext(ctx); err != nil {
			return req, ErrCancelled
		}
		det, err := d.Detect(ctx, strings.TrimSpace(raw))
		if err != nil {
			fmt.Fprintf(d.Out, "Could not classify that: %v\n", err)
			continue
		}
		ok := true
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title("Looks like " + target.Describe(det) + ". Correct?").Value(&ok),
		)).RunWithContext(ctx); err != nil {
			return req, ErrCancelled
		}
		if ok {
			t = det
			break
		}
	}
	req.Targets = []string{raw}

	// Step 2: profile with plan estimates.
	var opts []huh.Option[string]
	for _, name := range engine.ProfileNames() {
		p, _ := engine.ProfileByName(name)
		label := name + " — " + p.Description
		if d.Plan != nil {
			if lines, err := d.Plan(ctx, t, name); err == nil && len(lines) > 0 {
				label += " (" + strings.Join(lines, "; ") + ")"
			}
		}
		opts = append(opts, huh.NewOption(label, name))
	}
	if err := huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("How thorough?").Options(opts...).Value(&req.Profile),
	)).RunWithContext(ctx); err != nil {
		return req, ErrCancelled
	}

	// Step 3: authorization acknowledgment (public-target consent happens in
	// the safety gate, which shows the plan and asks for the hostname).
	if !d.Acknowledged {
		ack := false
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title(config.AckText).
				Description("Scanning systems you do not own or have written permission to test may be illegal.").
				Affirmative("I am authorised").Negative("Cancel").Value(&ack),
		)).RunWithContext(ctx); err != nil || !ack {
			return req, ErrCancelled
		}
		req.AckAuthorized = true
	}

	// Step 4: online disclosure (SCA only).
	if d.SCAApplies != nil && d.SCAApplies(t) {
		online := true
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().Title("Package names and versions will be sent to osv.dev to look up vulnerabilities. OK?").
				Affirmative("Yes, look them up").Negative("No, stay offline").Value(&online),
		)).RunWithContext(ctx); err != nil {
			return req, ErrCancelled
		}
		req.Offline = !online
	}

	// Step 5: output.
	req.Out = "./scnr-out"
	formats := []string{"html", "json"}
	if err := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Output directory").Description("Reports go in <dir>/<scan-id>/").Value(&req.Out),
		huh.NewMultiSelect[string]().Title("Formats").Options(
			huh.NewOption("HTML (read in a browser)", "html").Selected(true),
			huh.NewOption("JSON (machine-readable)", "json").Selected(true),
			huh.NewOption("SARIF (code scanning upload)", "sarif"),
			huh.NewOption("Markdown (PR comment)", "md"),
			huh.NewOption("CSV (spreadsheet)", "csv"),
		).Value(&formats),
	)).RunWithContext(ctx); err != nil {
		return req, ErrCancelled
	}
	if len(formats) > 0 {
		req.Formats = strings.Join(formats, ",")
	}
	return req, nil
}
