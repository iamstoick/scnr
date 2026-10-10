package report

import (
	"context"
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/store"
)

// CSV writes one flat row per finding for spreadsheet triage.
type CSV struct{ Meta Meta }

// Name implements Reporter.
func (c *CSV) Name() string { return "csv" }

// FileName implements Reporter.
func (c *CSV) FileName() string { return "report.csv" }

var csvHeader = []string{"fingerprint", "scan_id", "asset", "rule_id", "engine", "title", "severity", "confidence", "risk", "status",
	"location", "cwe", "cves", "cvss_score", "epss", "kev", "first_seen", "last_seen", "how_to_fix"}

// csvCell neutralises spreadsheet formula injection (a cell starting with
// = + - @ or a tab/CR is executed by Excel/Sheets when opened) and strips
// control characters. encoding/csv handles quoting.
func csvCell(s string) string {
	s = safety.StripControl(s)
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// Write implements Reporter.
func (c *CSV) Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		cvss, epss := "", ""
		if f.CVSS != nil {
			cvss = strconv.FormatFloat(f.CVSS.Score, 'f', 1, 64)
		}
		if f.EPSS != nil {
			epss = strconv.FormatFloat(*f.EPSS, 'f', 4, 64)
		}
		row := []string{f.Fingerprint, scan.ID, f.AssetKey, f.RuleID, f.Engine, f.Title, f.Severity.String(), f.Confidence.String(), strconv.Itoa(f.Risk), string(f.Status),
			f.Location, f.CWE, strings.Join(f.CVEs, " "), cvss, epss, strconv.FormatBool(f.KEV), f.FirstSeen.UTC().Format(time.RFC3339), f.LastSeen.UTC().Format(time.RFC3339), f.HowToFix}
		for i := range row {
			row[i] = csvCell(row[i])
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}
