package report

import (
	"bufio"
	"context"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/risk"
	"github.com/iamstoick/scnr/internal/safety"
	"github.com/iamstoick/scnr/internal/store"
)

// MarkdownMaxRows bounds the findings table (PR comments have size limits).
const MarkdownMaxRows = 500

// Markdown writes a summary plus a findings table, for PR comments.
type Markdown struct{ Meta Meta }

// Name implements Reporter.
func (m *Markdown) Name() string { return "md" }

// FileName implements Reporter.
func (m *Markdown) FileName() string { return "report.md" }

// mdCell makes hostile text safe inside a Markdown table cell rendered by
// GitHub and friends: HTML-escaped (no raw tags), pipes and newlines
// neutralised, link/image syntax ([, ], !) and backslashes escaped so a
// finding title cannot smuggle a tracking pixel or phishing link into a PR
// comment, control characters stripped, length capped. Used for every
// finding-derived string (titles, locations, HowToFix) in the report.
func mdCell(s string) string {
	s = safety.StripControl(s)
	s = strings.NewReplacer("\n", " ", "\t", " ", "\\", "\\\\", "|", "\\|", "[", "\\[", "]", "\\]", "!", "\\!", "`", "'").Replace(s)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return html.EscapeString(s)
}

// Write implements Reporter.
func (m *Markdown) Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	var counts risk.Counts
	var top []domain.Finding
	var rows []domain.Finding
	var suppressed []domain.Finding
	total := 0
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		total++
		counts.Add(f)
		switch f.Status {
		case domain.StatusAccepted, domain.StatusSuppressed:
			if len(suppressed) < MarkdownMaxRows {
				suppressed = append(suppressed, f)
			}
			continue
		case domain.StatusFixed:
			continue
		}
		if len(top) < TopFixesCount && f.HowToFix != "" {
			top = append(top, f)
		}
		if len(rows) < MarkdownMaxRows {
			rows = append(rows, f)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	var targets []string
	for _, t := range scan.Targets {
		targets = append(targets, "`"+mdCell(t.Value)+"`")
	}
	grade := scan.Posture.Grade
	if grade == "" {
		grade = risk.Grade(scan.Posture.Score)
	}
	partial := ""
	if scan.Partial {
		partial = " (partial)"
	}
	fmt.Fprintf(bw, "## scnr security report: %d/100, grade %s%s\n\n", scan.Posture.Score, mdCell(grade), partial)
	fmt.Fprintf(bw, "Scan `%s` · profile %s · %s · targets: %s\n\n", mdCell(scan.ID), mdCell(scan.Profile), scan.StartedAt.UTC().Format("2006-01-02 15:04 UTC"), strings.Join(targets, ", "))
	if m.Meta.PreviousScore != nil {
		fmt.Fprintf(bw, "Score change vs previous scan: %+d\n\n", scan.Posture.Score-*m.Meta.PreviousScore)
	}
	fmt.Fprintf(bw, "| Critical | High | Medium | Low | Info |\n|---:|---:|---:|---:|---:|\n| %d | %d | %d | %d | %d |\n\n", counts.Critical, counts.High, counts.Medium, counts.Low, counts.Info)
	if counts.KEVOpen {
		fmt.Fprintln(bw, "> An open finding is on CISA's Known Exploited Vulnerabilities list; the grade is capped at D until it is fixed.")
		fmt.Fprintln(bw)
	}
	if scan.Partial {
		fmt.Fprintln(bw, "> Some engines did not run or failed (see Coverage); the score only reflects what ran.")
		fmt.Fprintln(bw)
	}
	if len(top) > 0 {
		fmt.Fprintln(bw, "### Fix these first")
		fmt.Fprintln(bw)
		for i, f := range top {
			fmt.Fprintf(bw, "%d. **[%d] %s** — %s (`%s`%s)\n", i+1, f.Risk, mdCell(f.Title), mdCell(firstLineOf(f.HowToFix)), mdCell(f.AssetKey), locSuffix(f))
		}
		fmt.Fprintln(bw)
	}
	fmt.Fprintf(bw, "### Findings (%d open", len(rows))
	if total-len(rows)-len(suppressed) > 0 {
		fmt.Fprintf(bw, ", %d not shown", total-len(rows)-len(suppressed))
	}
	fmt.Fprintln(bw, ")")
	fmt.Fprintln(bw)
	if len(rows) == 0 {
		fmt.Fprintln(bw, "No open findings.")
	} else {
		fmt.Fprintln(bw, "| Risk | Severity | Rule | Asset | Location | Title |")
		fmt.Fprintln(bw, "|---:|---|---|---|---|---|")
		for _, f := range rows {
			kev := ""
			if f.KEV {
				kev = " **KEV**"
			}
			fmt.Fprintf(bw, "| %d | %s%s | `%s` | %s | %s | %s |\n", f.Risk, f.Severity, kev, mdCell(f.RuleID), mdCell(f.AssetKey), mdCell(f.Location), mdCell(f.Title))
		}
	}
	fmt.Fprintln(bw)
	if len(suppressed) > 0 {
		fmt.Fprintf(bw, "### Accepted / suppressed (%d)\n\n| Status | Risk | Rule | Location | Title |\n|---|---:|---|---|---|\n", len(suppressed))
		for _, f := range suppressed {
			fmt.Fprintf(bw, "| %s | %d | `%s` | %s | %s |\n", f.Status, f.Risk, mdCell(f.RuleID), mdCell(f.Location), mdCell(f.Title))
		}
		fmt.Fprintln(bw)
	}
	fmt.Fprintln(bw, "### Coverage")
	fmt.Fprintln(bw)
	fmt.Fprintln(bw, "| Engine | Version | Status |")
	fmt.Fprintln(bw, "|---|---|---|")
	for _, e := range scan.Engines {
		st := e.Status
		if e.Error != "" {
			st += ": " + e.Error
		}
		fmt.Fprintf(bw, "| %s | %s | %s |\n", mdCell(e.Name), mdCell(e.Version), mdCell(st))
	}
	fmt.Fprintln(bw)
	fmt.Fprintf(bw, "<sub>scnr %s · consent %s · scope %s · scnr observes and reports, it never exploits; evidence is redacted.</sub>\n", mdCell(m.Meta.Version), mdCell(scan.Consent.Method), mdCell(shortHash(scan.ScopeHash)))
	return bw.Flush()
}

func locSuffix(f domain.Finding) string {
	if f.Location == "" {
		return ""
	}
	return " at " + mdCell(f.Location)
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
