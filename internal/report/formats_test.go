package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/iamstoick/scnr/internal/domain"
	"github.com/iamstoick/scnr/internal/jsonschema"
)

// Acceptance 2.3: SARIF output validates against the 2.1.0 schema in testdata.
func TestSARIFValidatesAgainstSchema(t *testing.T) {
	schema, err := jsonschema.Load("../../testdata/sarif/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the validator rejects an obviously broken document.
	if errs, err := schema.Validate([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{}},"results":[{"message":{"text":"x"},"level":"loud"}]}]}`)); err != nil || len(errs) < 2 {
		t.Fatalf("validator too lenient: %v %v", errs, err)
	}
	s, sc := seed(t)
	var buf bytes.Buffer
	if err := (&SARIF{Meta: Meta{Version: "test"}}).Write(context.Background(), s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	errs, err := schema.Validate(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) > 0 {
		t.Fatalf("schema violations:\n%s\n%s", strings.Join(errs, "\n"), buf.String())
	}
	var log struct {
		Schema  string `json:"$schema"`
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct {
						ID         string
						Properties map[string]any
					}
				}
			}
			Results []struct {
				RuleID              string
				RuleIndex           int
				Level               string
				PartialFingerprints map[string]string
				Locations           []map[string]any
				Suppressions        []map[string]any
				Properties          map[string]any
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || log.Schema != SARIFSchemaURI || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "scnr/secrets" {
		t.Fatalf("header %+v", log)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 || len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("results %d rules %d", len(run.Results), len(run.Tool.Driver.Rules))
	}
	r0 := run.Results[0]
	if r0.RuleID != "secret.aws-access-key" || run.Tool.Driver.Rules[r0.RuleIndex].ID != r0.RuleID || r0.Level != "warning" || r0.PartialFingerprints["scnr/v1"] == "" {
		t.Fatalf("result0 %+v", r0)
	}
	phys := r0.Locations[0]["physicalLocation"].(map[string]any)
	if phys["artifactLocation"].(map[string]any)["uri"] != "a.py" || phys["region"].(map[string]any)["startLine"].(float64) != 1 {
		t.Fatalf("location %v", phys)
	}
	if run.Results[1].Suppressions == nil || run.Results[1].Suppressions[0]["status"] != "accepted" {
		t.Fatalf("accepted finding must carry a suppression: %+v", run.Results[1])
	}
	if run.Tool.Driver.Rules[0].Properties["security-severity"] != "9.5" {
		t.Fatalf("rule props %v", run.Tool.Driver.Rules[0].Properties)
	}
	if strings.Contains(buf.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("raw secret in SARIF")
	}
}

func TestSARIFLocations(t *testing.T) {
	roots := map[string]string{"repo:/r": "/r"}
	l := sarifLocationFor(domain.Finding{AssetKey: "repo:/r", RuleID: "secret.x", Location: "/r/src/a.py:12#abc"}, roots)
	if l.PhysicalLocation.ArtifactLocation.URI != "src/a.py" || l.PhysicalLocation.Region.StartLine != 12 {
		t.Fatalf("%+v", l.PhysicalLocation)
	}
	l = sarifLocationFor(domain.Finding{AssetKey: "url:http://x/", RuleID: "web.x", Location: "http://x/.env"}, roots)
	if l.PhysicalLocation == nil || l.PhysicalLocation.ArtifactLocation.URI != "http://x/.env" {
		t.Fatalf("%+v", l)
	}
	l = sarifLocationFor(domain.Finding{AssetKey: "host:10.0.0.5", RuleID: "net.open-port", Location: "10.0.0.5:22"}, roots)
	if len(l.LogicalLocations) != 1 || l.LogicalLocations[0].Name != "10.0.0.5:22" {
		t.Fatalf("%+v", l)
	}
	if ruleName("net.exposed-db-port") != "NetExposedDbPort" || ruleName("nuclei:CVE-2021-1") != "NucleiCVE20211" {
		t.Fatal(ruleName("net.exposed-db-port"))
	}
}

func TestMarkdownReport(t *testing.T) {
	s, sc := seed(t)
	prev := 80
	var buf bytes.Buffer
	if err := (&Markdown{Meta: Meta{Version: "test", PreviousScore: &prev}}).Write(context.Background(), s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"## scnr security report: 55/100, grade F (partial)", "Score change vs previous scan: -25", "### Fix these first", "Revoke it", "| Risk | Severity | Rule |", "`secret.aws-access-key`", "### Accepted / suppressed (1)", "### Coverage", "skipped: offline"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "<script>") {
		t.Fatal("hostile title not escaped")
	}
	if mdCell("a|b\nc`d") != "a\\|b c&#39;d" {
		t.Fatal(mdCell("a|b\nc`d"))
	}
}

func TestCSVReport(t *testing.T) {
	s, sc := seed(t)
	var buf bytes.Buffer
	if err := (&CSV{}).Write(context.Background(), s.Iterate(sc.ID), sc, &buf); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || len(rows[0]) != len(csvHeader) || rows[0][0] != "fingerprint" {
		t.Fatalf("rows %v", rows)
	}
	if rows[1][3] != "secret.aws-access-key" || rows[1][9] != "open" || rows[2][9] != "accepted" {
		t.Fatalf("rows %v", rows)
	}
	for _, in := range []string{"=HYPERLINK(1)", "+1", "-1", "@x", "\tcmd"} {
		if !strings.HasPrefix(csvCell(in), "'") {
			t.Errorf("formula not neutralised: %q", csvCell(in))
		}
	}
	if csvCell("plain") != "plain" {
		t.Fatal(csvCell("plain"))
	}
}

func TestRegistryHasAllFormats(t *testing.T) {
	reg := Registry(Meta{})
	rs, err := ParseFormats("html,json,sarif,md,csv", reg)
	if err != nil || len(rs) != 5 {
		t.Fatal(err)
	}
}
