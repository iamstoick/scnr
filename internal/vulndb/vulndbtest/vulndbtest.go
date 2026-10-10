// Package vulndbtest provides recorded OSV fixtures for offline-bundle
// tests: a fake GCS export server serving all.zip per ecosystem. Tests
// never touch the network.
package vulndbtest

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// LodashVuln is the recorded GHSA-p6mc-m468-83gw record (the same one the
// cli and sca fake OSV servers return), in OSV export shape.
func LodashVuln() map[string]any {
	return map[string]any{
		"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash", "details": "lodash before 4.17.21 is vulnerable. More text.",
		"aliases":  []string{"CVE-2020-8203"},
		"modified": "2024-01-01T00:00:00Z",
		"severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H"}},
		"affected": []map[string]any{{
			"package": map[string]string{"ecosystem": "npm", "name": "lodash", "purl": "pkg:npm/lodash"},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "3.7.0"}, {"fixed": "4.17.19"}}}},
		}, {
			"package": map[string]string{"ecosystem": "npm", "name": "lodash"},
			"ranges":  []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}}},
		}},
		"references":        []map[string]string{{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw"}},
		"database_specific": map[string]any{"severity": "HIGH", "cwe_ids": []string{"CWE-1321"}},
	}
}

// Zip packs OSV records as <id>.json entries of an all.zip.
func Zip(t *testing.T, records ...map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, r := range records {
		name, _ := r["id"].(string)
		if name == "" {
			name = "record-" + string(rune('a'+i))
		}
		w, err := zw.Create(name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(w).Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// GCSServer serves /<Ecosystem>/all.zip from zips and 404 otherwise. When
// redirectTo is non-empty every request is redirected there instead (for
// the endpoint-allowlist invariant).
func GCSServer(t *testing.T, zips map[string][]byte, redirectTo string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectTo != "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 2 || parts[1] != "all.zip" {
			http.NotFound(w, r)
			return
		}
		z, ok := zips[parts[0]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Write(z)
	}))
	t.Cleanup(srv.Close)
	return srv
}
