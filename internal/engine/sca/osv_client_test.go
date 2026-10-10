package sca

import (
	"context"
	"strings"
	"testing"
)

// A nil HTTP client is an error, never http.DefaultClient (SAFETY.md item
// 9): the engine's default OSVClient only works once the CLI injects an
// endpoint client.
func TestOSVClientNoHTTP(t *testing.T) {
	c := &OSVClient{Base: "http://127.0.0.1:1"}
	if _, err := c.QueryBatch(context.Background(), []Package{{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}}); err == nil || !strings.Contains(err.Error(), "no HTTP client") {
		t.Fatalf("want no-client error, got %v", err)
	}
}
