package sca

import (
	"math"
	"strings"
)

// cvssV3BaseScore computes the CVSS v3.x base score from a vector string.
// Returns 0 for malformed vectors. Implemented here (≈40 lines) rather than
// pulling a dependency.
func cvssV3BaseScore(vector string) float64 {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scopeChanged := m["S"] == "C"
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scopeChanged {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scopeChanged {
			pr = 0.5
		}
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, cok := cia[m["C"]]
	i, iok := cia[m["I"]]
	a, aok := cia[m["A"]]
	if av == 0 || ac == 0 || ui == 0 || pr == 0 || !cok || !iok || !aok {
		return 0
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	var score float64
	if scopeChanged {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return roundUp1(score)
}

// roundUp1 is CVSS "Roundup" to one decimal.
func roundUp1(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
