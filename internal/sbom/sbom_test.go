package sbom

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/jsonschema"
)

func schema(t *testing.T) *jsonschema.Validator {
	t.Helper()
	v, err := jsonschema.Load("../../testdata/cyclonedx/bom-1.5.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the validator rejects a broken BOM.
	if errs, err := v.Validate([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"spaceship","name":"x"}]}`)); err != nil || len(errs) == 0 {
		t.Fatalf("validator too lenient: %v %v", errs, err)
	}
	return v
}

func imageEngine(t *testing.T) *image.Engine {
	t.Helper()
	s, _ := sca.New(nil)
	e, err := image.New(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// Acceptance 3.2: scnr sbom output validates against the CycloneDX 1.5 schema.
func TestWriteValidatesAgainstSchema(t *testing.T) {
	v := schema(t)
	repo, _ := filepath.Abs("../../testdata/phase3-repo")
	inv, err := Collect(context.Background(), domain.Target{Type: domain.TargetPath, Value: repo}, imageEngine(t))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, inv, "test", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	errs, err := v.Validate(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) > 0 {
		t.Fatalf("schema violations:\n%s\n%s", strings.Join(errs, "\n"), buf.String())
	}
	var bom struct {
		BOMFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Metadata    struct {
			Component struct{ Type, Name string }
			Tools     struct {
				Components []struct{ Name, Version string }
			}
		}
		Components []struct {
			Type, Name, Version, PURL, BOMRef string                         `json:"-"`
			P                                 string                         `json:"purl"`
			Ref                               string                         `json:"bom-ref"`
			Props                             []struct{ Name, Value string } `json:"properties"`
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Metadata.Component.Type != "application" || bom.Metadata.Tools.Components[0].Name != "scnr" {
		t.Fatalf("%+v", bom.Metadata)
	}
	if len(bom.Components) != len(inv.Packages) || len(bom.Components) < 20 {
		t.Fatalf("%d components for %d packages", len(bom.Components), len(inv.Packages))
	}
	purls := map[string]bool{}
	for _, c := range bom.Components {
		if c.P == "" || c.Ref != c.P || purls[c.P] {
			t.Fatalf("component %+v", c)
		}
		purls[c.P] = true
	}
	for _, want := range []string{"pkg:npm/lodash@4.17.20", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:gem/nokogiri@1.13.0", "pkg:cargo/openssl@0.10.55", "pkg:composer/symfony/http-kernel@5.4.20", "pkg:golang/golang.org/x/text@v0.3.0"} {
		if !purls[want] {
			t.Errorf("missing %s", want)
		}
	}
	// Deterministic apart from the serial number.
	var again bytes.Buffer
	Write(&again, inv, "test", time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC))
	strip := func(b []byte) string { return string(bytes.Split(b, []byte(`"serialNumber"`))[1][60:]) }
	if strip(buf.Bytes()) != strip(again.Bytes()) {
		t.Fatal("output not deterministic")
	}
}

func TestImageBOMAndHostileStrings(t *testing.T) {
	v := schema(t)
	tarPath, _ := filepath.Abs("../../testdata/image/alpine-small.tar")
	tg := domain.Target{Type: domain.TargetImage, Value: tarPath, Labels: map[string]string{image.SourceLabel: image.SourceDockerTar}}
	inv, err := Collect(context.Background(), tg, imageEngine(t))
	if err != nil || inv.OS == nil || inv.OS.ID != "alpine" || len(inv.Packages) != 6 {
		t.Fatalf("%+v %v", inv, err)
	}
	var buf bytes.Buffer
	if err := Write(&buf, inv, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if errs, _ := v.Validate(buf.Bytes()); len(errs) > 0 {
		t.Fatalf("%v", errs)
	}
	if !strings.Contains(buf.String(), `"type": "container"`) || !strings.Contains(buf.String(), "pkg:apk/alpine/libcrypto3@3.1.4-r1") || !strings.Contains(buf.String(), `"scnr:upstream"`) {
		t.Fatal(buf.String())
	}
	// Registry references and other target types are refused.
	if _, err := Collect(context.Background(), domain.Target{Type: domain.TargetImage, Value: "alpine:3.18"}, imageEngine(t)); err == nil || !strings.Contains(err.Error(), "docker save") {
		t.Fatalf("%v", err)
	}
	if _, err := Collect(context.Background(), domain.Target{Type: domain.TargetURL, Value: "http://x/"}, imageEngine(t)); err == nil {
		t.Fatal("url accepted")
	}
	// Hostile package names/versions from a lockfile are control-stripped and
	// redacted, and still produce a valid document.
	hostile := &Inventory{Target: domain.Target{Type: domain.TargetPath, Value: "/r"}, Packages: []sca.Package{
		{Ecosystem: "npm", Name: "evil\x00\x1b[31m</script>", Version: "1.0.0\"},{\"injected\":true", File: "package-lock.json"},
		{Ecosystem: "PyPI", Name: "token", Version: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", File: "requirements.txt"},
	}}
	buf.Reset()
	if err := Write(&buf, hostile, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if errs, _ := v.Validate(buf.Bytes()); len(errs) > 0 {
		t.Fatalf("%v", errs)
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij") {
		t.Fatalf("hostile content leaked: %s", out)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("injection broke the document: %v", err)
	}
	if _, ok := doc["injected"]; ok {
		t.Fatal("JSON injection succeeded")
	}
	// Component cap recorded as a property.
	many := &Inventory{Target: domain.Target{Type: domain.TargetPath, Value: "/r"}}
	for i := 0; i < MaxComponents+5; i++ {
		many.Packages = append(many.Packages, sca.Package{Ecosystem: "npm", Name: "p" + itoa(i), Version: "1"})
	}
	buf.Reset()
	if err := Write(&buf, many, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "5 components omitted") {
		t.Fatal("truncation not recorded")
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
