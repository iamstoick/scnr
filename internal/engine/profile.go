package engine

import (
	"fmt"
	"time"
)

// Profile sizes a scan (Section 5.2).
type Profile struct {
	Name               string
	Ports              string // top100 | top1000
	MaxParallelEngines int64
	EngineTimeout      time.Duration // 0 = none
	Engines            []string      // nil = all registered
	Description        string
}

var profiles = map[string]Profile{
	"quick": {
		Name: "quick", Ports: "top100", MaxParallelEngines: 4, EngineTimeout: 2 * time.Minute,
		Engines:     []string{"netscan", "secrets", "sca"},
		Description: "top 100 ports, secrets + SCA (~2 min)",
	},
	"standard": {
		Name: "standard", Ports: "top1000", MaxParallelEngines: 4, EngineTimeout: 10 * time.Minute,
		Description: "top 1000 ports, TLS checks, all native engines (~10 min)",
	},
	"deep": {
		Name: "deep", Ports: "top1000", MaxParallelEngines: 4, EngineTimeout: 0,
		Description: "everything available, no time cap",
	},
}

// ProfileByName returns a profile or an error listing the valid names.
func ProfileByName(name string) (Profile, error) {
	if name == "" {
		name = "standard"
	}
	p, ok := profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile %q (quick|standard|deep)", name)
	}
	return p, nil
}

// ProfileNames in display order.
func ProfileNames() []string { return []string{"quick", "standard", "deep"} }

func (p Profile) allowsEngine(name string) bool {
	if p.Engines == nil {
		return true
	}
	for _, e := range p.Engines {
		if e == name {
			return true
		}
	}
	return false
}
