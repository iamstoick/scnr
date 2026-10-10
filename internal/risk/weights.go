// Package risk implements the Section 7 formulas. Every constant lives in
// this file so `scnr config show --risk` can print them.
package risk

// Base scores when no CVSS is available, by Severity.
var SeverityBase = map[string]float64{
	"critical": 95, "high": 80, "medium": 55, "low": 25, "info": 5,
}

// Exploitability multipliers.
const (
	ExploitKEV       = 1.00 // KEV listed or EPSS >= EPSSHigh
	ExploitEPSSMid   = 0.85 // EPSSLow <= EPSS < EPSSHigh
	ExploitEPSSLow   = 0.70 // EPSS < EPSSLow
	ExploitUnknown   = 0.80 // no CVE / EPSS unknown
	EPSSHigh         = 0.10
	EPSSLow          = 0.01
	KEVFloor         = 90 // any KEV finding has Risk >= KEVFloor
	CVSSToBaseFactor = 10
)

// Exposure multipliers.
const (
	ExposurePublic  = 1.00
	ExposurePrivate = 0.85
	ExposureLocal   = 0.80
)

// Confidence multipliers.
const (
	ConfConfirmed = 1.00
	ConfFirm      = 0.90
	ConfTentative = 0.75
)

// Risk bucket thresholds (inclusive lower bounds).
const (
	BucketCritical = 90
	BucketHigh     = 70
	BucketMedium   = 40
	BucketLow      = 10
)

// Posture deductions: first, each subsequent, cap.
type Deduction struct{ First, Each, Cap int }

var (
	DeductCritical = Deduction{25, 10, 60}
	DeductHigh     = Deduction{10, 4, 30}
	DeductMedium   = Deduction{3, 1, 15}
	DeductLow      = Deduction{1, 1, 5}
)

// Grade thresholds.
const (
	GradeA = 90
	GradeB = 80
	GradeC = 70
	GradeD = 60
)

// KEVGradeCap is the best grade a scan with an open KEV finding can show.
const KEVGradeCap = "D"
