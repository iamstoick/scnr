package risk

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/iamstoick/scnr/internal/domain"
)

// Exposure of the asset a finding belongs to.
type Exposure int

const (
	Public Exposure = iota
	Private
	Local
)

// ExposureFor maps a target's type and publicness to an Exposure.
func ExposureFor(t domain.TargetType, public bool) Exposure {
	switch t {
	case domain.TargetPath, domain.TargetImage:
		return Local
	}
	if public {
		return Public
	}
	return Private
}

// Score computes the 0-100 Risk for a finding (Section 7).
func Score(f domain.Finding, exp Exposure) int {
	var base float64
	if f.CVSS != nil && f.CVSS.Score > 0 {
		base = f.CVSS.Score * CVSSToBaseFactor
	} else {
		base = SeverityBase[f.Severity.String()]
	}
	e := ExploitUnknown
	switch {
	case f.KEV:
		e = ExploitKEV
	case f.EPSS != nil && *f.EPSS >= EPSSHigh:
		e = ExploitKEV
	case f.EPSS != nil && *f.EPSS >= EPSSLow:
		e = ExploitEPSSMid
	case f.EPSS != nil:
		e = ExploitEPSSLow
	}
	x := ExposureLocal
	switch exp {
	case Public:
		x = ExposurePublic
	case Private:
		x = ExposurePrivate
	}
	c := ConfTentative
	switch f.Confidence {
	case domain.Confirmed:
		c = ConfConfirmed
	case domain.Firm:
		c = ConfFirm
	}
	r := int(math.Round(base * e * x * c))
	if r < 0 {
		r = 0
	}
	if r > 100 {
		r = 100
	}
	if f.KEV && r < KEVFloor {
		r = KEVFloor
	}
	return r
}

// Bucket names a risk value.
func Bucket(r int) string {
	switch {
	case r >= BucketCritical:
		return "critical"
	case r >= BucketHigh:
		return "high"
	case r >= BucketMedium:
		return "medium"
	case r >= BucketLow:
		return "low"
	}
	return "info"
}

// Counts of open findings per bucket.
type Counts struct {
	Critical, High, Medium, Low, Info int
	KEVOpen                           bool
}

// Add tallies one finding into the counts if it is open.
func (c *Counts) Add(f domain.Finding) {
	if f.Status != "" && f.Status != domain.StatusOpen {
		return
	}
	switch Bucket(f.Risk) {
	case "critical":
		c.Critical++
	case "high":
		c.High++
	case "medium":
		c.Medium++
	case "low":
		c.Low++
	default:
		c.Info++
	}
	if f.KEV {
		c.KEVOpen = true
	}
}

func deduct(n int, d Deduction) int {
	if n <= 0 {
		return 0
	}
	v := d.First + (n-1)*d.Each
	if v > d.Cap {
		v = d.Cap
	}
	return v
}

// Posture computes the scan score and grade.
func Posture(c Counts, partial bool) domain.PostureScore {
	score := 100 - deduct(c.Critical, DeductCritical) - deduct(c.High, DeductHigh) - deduct(c.Medium, DeductMedium) - deduct(c.Low, DeductLow)
	if score < 0 {
		score = 0
	}
	grade := Grade(score)
	if c.KEVOpen && grade < KEVGradeCap {
		grade = KEVGradeCap
	}
	return domain.PostureScore{
		Score:   score,
		Grade:   grade,
		Partial: partial,
		KEVOpen: c.KEVOpen,
		Counts: map[string]int{
			"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "info": c.Info,
		},
		Explain: Explain(),
	}
}

// Grade letter for a score.
func Grade(score int) string {
	switch {
	case score >= GradeA:
		return "A"
	case score >= GradeB:
		return "B"
	case score >= GradeC:
		return "C"
	case score >= GradeD:
		return "D"
	}
	return "F"
}

// TopFixes returns the n highest-risk open findings with a HowToFix.
func TopFixes(findings []domain.Finding, n int) []domain.Finding {
	var out []domain.Finding
	for _, f := range findings {
		if f.Status == "" || f.Status == domain.StatusOpen {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Explain renders the constants for `scnr config show --risk`.
func Explain() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Risk = clamp(round(base * E * X * C), 0, 100); KEV floor %d\n", KEVFloor)
	fmt.Fprintf(&b, "  base: CVSS*%d if present else critical=%.0f high=%.0f medium=%.0f low=%.0f info=%.0f\n", CVSSToBaseFactor,
		SeverityBase["critical"], SeverityBase["high"], SeverityBase["medium"], SeverityBase["low"], SeverityBase["info"])
	fmt.Fprintf(&b, "  E: %.2f KEV or EPSS>=%.2f | %.2f EPSS>=%.2f | %.2f EPSS<%.2f | %.2f unknown\n", ExploitKEV, EPSSHigh, ExploitEPSSMid, EPSSLow, ExploitEPSSLow, EPSSLow, ExploitUnknown)
	fmt.Fprintf(&b, "  X: %.2f public | %.2f private | %.2f local\n", ExposurePublic, ExposurePrivate, ExposureLocal)
	fmt.Fprintf(&b, "  C: %.2f confirmed | %.2f firm | %.2f tentative\n", ConfConfirmed, ConfFirm, ConfTentative)
	fmt.Fprintf(&b, "Buckets: critical>=%d high>=%d medium>=%d low>=%d\n", BucketCritical, BucketHigh, BucketMedium, BucketLow)
	fmt.Fprintf(&b, "Posture: 100 - critical(%d,+%d,cap %d) - high(%d,+%d,cap %d) - medium(%d,+%d,cap %d) - low(%d each,cap %d)\n",
		DeductCritical.First, DeductCritical.Each, DeductCritical.Cap, DeductHigh.First, DeductHigh.Each, DeductHigh.Cap,
		DeductMedium.First, DeductMedium.Each, DeductMedium.Cap, DeductLow.Each, DeductLow.Cap)
	fmt.Fprintf(&b, "Grade: A>=%d B>=%d C>=%d D>=%d else F; open KEV caps grade at %s\n", GradeA, GradeB, GradeC, GradeD, KEVGradeCap)
	return b.String()
}
