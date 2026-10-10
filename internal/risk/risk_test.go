package risk

import (
	"strings"
	"testing"

	"github.com/gerald/scnr/internal/domain"
)

func fp(v float64) *float64 { return &v }

func TestScoreFormula(t *testing.T) {
	cases := []struct {
		name string
		f    domain.Finding
		exp  Exposure
		want int
	}{
		// base 95 * E 0.80 (unknown) * X 1.00 * C 1.00 = 76
		{"critical public confirmed no cve", domain.Finding{Severity: domain.Critical, Confidence: domain.Confirmed}, Public, 76},
		// 95 * 0.80 * 0.80 * 0.90 = 54.72 -> 55 (the secrets case)
		{"critical local firm", domain.Finding{Severity: domain.Critical, Confidence: domain.Firm}, Local, 55},
		// 80 * 0.80 * 0.85 * 0.75 = 40.8 -> 41
		{"high private tentative", domain.Finding{Severity: domain.High, Confidence: domain.Tentative}, Private, 41},
		// CVSS 9.8 -> base 98; EPSS 0.5 -> E 1.0; public confirmed -> 98
		{"cvss + high epss", domain.Finding{CVSS: &domain.CVSS{Score: 9.8}, EPSS: fp(0.5), Confidence: domain.Confirmed}, Public, 98},
		// base 55 * 0.85 * 1 * 1 = 46.75 -> 47
		{"medium mid epss", domain.Finding{Severity: domain.Medium, EPSS: fp(0.05), Confidence: domain.Confirmed}, Public, 47},
		// base 55 * 0.70 = 38.5 -> 39 (banker's? math.Round -> 39)
		{"medium low epss", domain.Finding{Severity: domain.Medium, EPSS: fp(0.001), Confidence: domain.Confirmed}, Public, 39},
		// KEV floor: low severity KEV finding: 25*1*1*1 = 25 -> floored to 90
		{"kev floor", domain.Finding{Severity: domain.Low, KEV: true, Confidence: domain.Confirmed}, Public, 90},
		// clamp: cvss 10 * 10 = 100 * 1 * 1 * 1 = 100
		{"clamp top", domain.Finding{CVSS: &domain.CVSS{Score: 10}, KEV: true, Confidence: domain.Confirmed}, Public, 100},
		// info: 5 * 0.8 * 0.85 * 1 = 3.4 -> 3
		{"info private", domain.Finding{Severity: domain.Info, Confidence: domain.Confirmed}, Private, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Score(c.f, c.exp); got != c.want {
				t.Fatalf("Score = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBuckets(t *testing.T) {
	for r, want := range map[int]string{100: "critical", 90: "critical", 89: "high", 70: "high", 69: "medium", 40: "medium", 39: "low", 10: "low", 9: "info", 0: "info"} {
		if got := Bucket(r); got != want {
			t.Errorf("Bucket(%d) = %s, want %s", r, got, want)
		}
	}
}

func TestPostureFormula(t *testing.T) {
	cases := []struct {
		name  string
		c     Counts
		score int
		grade string
	}{
		{"clean", Counts{}, 100, "A"},
		{"one critical", Counts{Critical: 1}, 75, "C"},
		{"two critical", Counts{Critical: 2}, 65, "D"},
		{"critical cap 60", Counts{Critical: 20}, 40, "F"},
		{"one high", Counts{High: 1}, 90, "A"},
		{"three high", Counts{High: 3}, 82, "B"},
		{"high cap 30", Counts{High: 50}, 70, "C"},
		{"one medium", Counts{Medium: 1}, 97, "A"},
		{"medium cap 15", Counts{Medium: 100}, 85, "B"},
		{"low cap 5", Counts{Low: 9}, 95, "A"},
		{"info free", Counts{Info: 500}, 100, "A"},
		{"floor zero", Counts{Critical: 20, High: 50, Medium: 100, Low: 9}, 0, "F"},
		{"kev caps grade at D", Counts{Low: 1, KEVOpen: true}, 99, "D"},
		{"kev does not raise F", Counts{Critical: 20, KEVOpen: true}, 40, "F"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Posture(c.c, false)
			if p.Score != c.score || p.Grade != c.grade {
				t.Fatalf("Posture = %d %s, want %d %s", p.Score, p.Grade, c.score, c.grade)
			}
		})
	}
	if !Posture(Counts{}, true).Partial {
		t.Fatal("partial flag lost")
	}
}

func TestCountsSkipNonOpen(t *testing.T) {
	var c Counts
	c.Add(domain.Finding{Risk: 95, Status: domain.StatusAccepted})
	c.Add(domain.Finding{Risk: 95, Status: domain.StatusSuppressed})
	c.Add(domain.Finding{Risk: 95, Status: domain.StatusOpen, KEV: true})
	c.Add(domain.Finding{Risk: 50})
	if c.Critical != 1 || c.Medium != 1 || !c.KEVOpen {
		t.Fatalf("counts = %+v", c)
	}
}

func TestExposureFor(t *testing.T) {
	if ExposureFor(domain.TargetPath, true) != Local || ExposureFor(domain.TargetHost, true) != Public || ExposureFor(domain.TargetURL, false) != Private {
		t.Fatal("exposure mapping")
	}
}

func TestExplainMentionsConstants(t *testing.T) {
	s := Explain()
	for _, want := range []string{"KEV floor 90", "critical>=90", "A>=90"} {
		if !strings.Contains(s, want) {
			t.Errorf("Explain missing %q", want)
		}
	}
}
