package report

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/risk"
	"github.com/iamstoick/scnr/internal/store"
)

//go:embed html/*.tmpl html/*.css
var htmlAssets embed.FS

// HTMLMaxFindings bounds how many findings the single-file HTML lists so
// memory stays flat for huge scans; the JSON report always has everything.
const HTMLMaxFindings = 5000

// TopFixesCount shown in "Fix these first".
const TopFixesCount = 10

// HTML writes a single self-contained file (html/template + embedded CSS,
// no JS, no external assets).
type HTML struct {
	Meta Meta
	tmpl *template.Template
}

// Name implements Reporter.
func (h *HTML) Name() string { return "html" }

// FileName implements Reporter.
func (h *HTML) FileName() string { return "report.html" }

type htmlAsset struct {
	Key      string
	Findings []domain.Finding
	MaxRisk  int
}

type htmlData struct {
	Scan          domain.Scan
	Version       string
	GeneratedAt   string
	CSS           template.CSS
	Score         int
	Grade         string
	Partial       bool
	DeltaText     string
	Counts        map[string]int
	KEVOpen       bool
	TopFixes      []domain.Finding
	Assets        []htmlAsset
	Suppressed    []domain.Finding
	Total         int
	Truncated     bool
	ExploitData   bool
	Explain       string
	TargetSummary string
}

func (h *HTML) load() error {
	if h.tmpl != nil {
		return nil
	}
	funcs := template.FuncMap{
		"bucket":   risk.Bucket,
		"sevName":  func(s domain.Severity) string { return s.String() },
		"confName": func(c domain.Confidence) string { return c.String() },
		"join":     strings.Join,
		"dur":      func(d time.Duration) string { return d.Round(time.Millisecond).String() },
		"short": func(s string) string {
			if len(s) > 12 {
				return s[:12]
			}
			return s
		},
		"inc": func(i int) int { return i + 1 },
		// mul multiplies two ints (used for bar/ring width calculations in the template).
		"mul": func(a, b int) int { return a * b },
		// div100 divides an int by 100, returning an int (used for score ring arc length).
		"div100": func(a int) int { return a / 100 },
		// divInt divides a by b safely, returning an int percentage.
		"divInt": func(b, a int) int {
			if b == 0 {
				return 0
			}
			return a / b
		},
		// hasPrefix wraps strings.HasPrefix for use in templates.
		"hasPrefix": strings.HasPrefix,
	}
	t, err := template.New("report.tmpl").Funcs(funcs).ParseFS(htmlAssets, "html/report.tmpl")
	if err != nil {
		return err
	}
	h.tmpl = t
	return nil
}

// Write implements Reporter.
func (h *HTML) Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error {
	if err := h.load(); err != nil {
		return err
	}
	css, err := htmlAssets.ReadFile("html/report.css")
	if err != nil {
		return err
	}
	byAsset := map[string]*htmlAsset{}
	var order []string
	var suppressed []domain.Finding
	var top []domain.Finding
	total := 0
	truncated := false
	var counts risk.Counts
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		total++
		counts.Add(f)
		if f.Status == domain.StatusAccepted || f.Status == domain.StatusSuppressed {
			if len(suppressed) < HTMLMaxFindings {
				suppressed = append(suppressed, f)
			}
			continue
		}
		if len(top) < TopFixesCount && f.HowToFix != "" {
			top = append(top, f)
		}
		if total > HTMLMaxFindings {
			truncated = true
			continue
		}
		a := byAsset[f.AssetKey]
		if a == nil {
			a = &htmlAsset{Key: f.AssetKey}
			byAsset[f.AssetKey] = a
			order = append(order, f.AssetKey)
		}
		if f.Risk > a.MaxRisk {
			a.MaxRisk = f.Risk
		}
		a.Findings = append(a.Findings, f)
	}
	if err := it.Err(); err != nil {
		return err
	}
	assets := make([]htmlAsset, 0, len(order))
	for _, k := range order {
		assets = append(assets, *byAsset[k])
	}
	sort.SliceStable(assets, func(i, j int) bool { return assets[i].MaxRisk > assets[j].MaxRisk })

	deltaText := ""
	if h.Meta.PreviousScore != nil {
		deltaText = fmt.Sprintf("%+d vs previous scan", scan.Posture.Score-*h.Meta.PreviousScore)
	}
	var targets []string
	for _, t := range scan.Targets {
		targets = append(targets, t.Value)
	}
	data := htmlData{
		Scan: scan, Version: h.Meta.Version, GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		CSS:   template.CSS(css), //nolint:gosec // embedded, not user input
		Score: scan.Posture.Score, Grade: scan.Posture.Grade, Partial: scan.Partial, DeltaText: deltaText,
		Counts:  map[string]int{"critical": counts.Critical, "high": counts.High, "medium": counts.Medium, "low": counts.Low, "info": counts.Info},
		KEVOpen: counts.KEVOpen, TopFixes: top, Assets: assets, Suppressed: suppressed, Total: total, Truncated: truncated,
		ExploitData: h.Meta.ExploitData, Explain: risk.Explain(), TargetSummary: strings.Join(targets, ", "),
	}
	if data.Grade == "" {
		data.Grade = risk.Grade(data.Score)
	}
	return h.tmpl.Execute(w, data)
}

// ScoreLine is the one-line summary printed by the CLI.
func ScoreLine(scan domain.Scan) string {
	s := fmt.Sprintf("Posture score %d/100, grade %s", scan.Posture.Score, scan.Posture.Grade)
	if scan.Partial {
		s += " (partial)"
	}
	return s
}
