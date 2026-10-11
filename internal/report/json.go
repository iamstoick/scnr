package report

import (
	"bufio"
	"context"
	"encoding/json"
	"io"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/store"
)

// JSON writes {schema_version, scan, assets[], findings[]} streaming the
// findings array.
type JSON struct{ Meta Meta }

// Name implements Reporter.
func (j *JSON) Name() string { return "json" }

// FileName implements Reporter.
func (j *JSON) FileName() string { return "report.json" }

type jsonHeader struct {
	SchemaVersion string      `json:"schema_version"`
	Generator     string      `json:"generator"`
	Scan          domain.Scan `json:"scan"`
	PreviousScore *int        `json:"previous_score,omitempty"`
	ExploitData   bool        `json:"exploit_data_available"`
}

// Write implements Reporter. Findings are written one object at a time;
// assets are collected from their keys as we go and written last.
func (j *JSON) Write(ctx context.Context, it *store.FindingIterator, scan domain.Scan, w io.Writer) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	hdr, err := json.Marshal(jsonHeader{SchemaVersion: SchemaVersion, Generator: "scnr " + j.Meta.Version, Scan: scan, PreviousScore: j.Meta.PreviousScore, ExploitData: j.Meta.ExploitData})
	if err != nil {
		return err
	}
	// Open the object: splice our header fields then the arrays.
	if _, err := bw.Write(hdr[:len(hdr)-1]); err != nil {
		return err
	}
	if _, err := bw.WriteString(`,"findings":[`); err != nil {
		return err
	}
	seen := map[string]bool{}
	var keys []string
	first := true
	for {
		f, ok := it.Next(ctx)
		if !ok {
			break
		}
		if !seen[f.AssetKey] {
			seen[f.AssetKey] = true
			keys = append(keys, f.AssetKey)
		}
		if !first {
			if err := bw.WriteByte(','); err != nil {
				return err
			}
		}
		first = false
		b, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err := bw.Write(b); err != nil {
			return err
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	if _, err := bw.WriteString(`],"assets":`); err != nil {
		return err
	}
	assets, err := json.Marshal(assetsFor(scan, keys))
	if err != nil {
		return err
	}
	if _, err := bw.Write(assets); err != nil {
		return err
	}
	if _, err := bw.WriteString("}\n"); err != nil {
		return err
	}
	return bw.Flush()
}
