package adapter

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine"
	"github.com/gerald/scnr/internal/engine/sca"
)

// SCABase is the shared scaffolding of adapters that emit shared-scheme SCA
// findings over a directory or a local image archive (trivy, grype): the
// exec Base, the borrowed sca rule prose, and the scan root/asset key the
// parser needs to relativise paths.
type SCABase struct {
	Base
	Rules    engine.RuleSet
	Root     string
	AssetKey string
	Output   string // report file name inside Scratch
}

// NewSCABase builds the base, borrowing prose from the sca engine.
func NewSCABase(binary, minVersion, output string, setEnv ...string) (SCABase, error) {
	s, err := sca.New(nil)
	if err != nil {
		return SCABase{}, err
	}
	return SCABase{Base: Base{BinaryName: binary, Min: minVersion, SetEnv: setEnv}, Rules: s.Rules(), Output: output}, nil
}

// Supports path and image targets.
func (b *SCABase) Supports(t domain.Target) bool {
	return t.Type == domain.TargetPath || t.Type == domain.TargetImage
}

// OutputPath is the report file the tool is told to write.
func (b *SCABase) OutputPath(o engine.Options) string { return filepath.Join(o.Scratch, b.Output) }

// RunSCA records the scan root and asset key, then runs the tool and parses
// its report file.
func (b *SCABase) RunSCA(ctx context.Context, ad Adapter, t domain.Target, o engine.Options, emit engine.EmitFunc) error {
	b.Root, b.AssetKey = t.Value, t.AssetKey()
	return b.RunTool(ctx, ad, t, o, emit, b.OutputPath(o))
}

// StringList accepts a JSON string or array of strings; nuclei and semgrep
// emit both shapes for classification/metadata fields across versions. An
// unexpected shape drops the field rather than the whole result.
type StringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		*s = nil
		return nil
	}
	*s = many
	return nil
}
