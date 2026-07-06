package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	cpeskills "github.com/scagogogo/cpe-skills"
)

// makeToolReq builds a CallToolRequest with the given JSON arguments.
func makeToolReq(t *testing.T, args string) *mcp.CallToolRequest {
	t.Helper()
	return &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{
			Name:      "test",
			Arguments: json.RawMessage(args),
		},
	}
}

// textOf extracts the text content from a CallToolResult.
func textOf(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	if tc, ok := r.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

func TestDetectFormat(t *testing.T) {
	tests := map[string]string{
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*": "2.3",
		"cpe:/a:apache:log4j:2.0":                      "2.2",
		"not-a-cpe":                                    "unknown",
		"":                                             "unknown",
	}
	for in, want := range tests {
		if got := detectFormat(in); got != want {
			t.Errorf("detectFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestComparisonMeaning(t *testing.T) {
	if got := comparisonMeaning(-1); got != "a < b" {
		t.Errorf("comparisonMeaning(-1) = %q", got)
	}
	if got := comparisonMeaning(0); got != "a == b" {
		t.Errorf("comparisonMeaning(0) = %q", got)
	}
	if got := comparisonMeaning(1); got != "a > b" {
		t.Errorf("comparisonMeaning(1) = %q", got)
	}
}

func TestArgsOf(t *testing.T) {
	if m := argsOf(nil); len(m) != 0 {
		t.Errorf("argsOf(nil) should be empty")
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{}}
	if m := argsOf(req); len(m) != 0 {
		t.Errorf("argsOf(empty) should be empty")
	}

	req = makeToolReq(t, `{"cpe":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*","to":"2.2"}`)
	m := argsOf(req)
	if v := argString(m, "cpe"); v != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
		t.Errorf("cpe arg = %q", v)
	}
	if v := argString(m, "to"); v != "2.2" {
		t.Errorf("to arg = %q", v)
	}
	if argBool(m, "missing") {
		t.Error("argBool on missing key should be false")
	}

	// invalid JSON -> empty map
	req = makeToolReq(t, `{not valid json`)
	if m := argsOf(req); len(m) != 0 {
		t.Errorf("argsOf(invalid) should be empty, got %v", m)
	}
}

func TestRegisterMCPTools_NoPanic(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "cpe-skills", Version: "test"}, nil)
	registerMCPTools(srv) // must not panic; all 6 tools wired
}

func TestToolJSONAndError(t *testing.T) {
	r, err := toolJSON(map[string]any{"match": true})
	if err != nil {
		t.Fatalf("toolJSON error: %v", err)
	}
	if r.IsError {
		t.Error("toolJSON should not set IsError")
	}
	if !strings.Contains(textOf(t, r), `"match": true`) {
		t.Errorf("toolJSON output unexpected: %s", textOf(t, r))
	}

	re := toolError("boom")
	if !re.IsError {
		t.Error("toolError should set IsError")
	}
	if textOf(t, re) != "boom" {
		t.Errorf("toolError text = %q", textOf(t, re))
	}
}

func TestRawSchema(t *testing.T) {
	s := rawSchema(`{"type":"object","properties":{"a":{"type":"string"}}}`)
	m, ok := s.(map[string]any)
	if !ok {
		t.Fatalf("rawSchema did not return a map")
	}
	if m["type"] != "object" {
		t.Errorf("type = %v", m["type"])
	}

	// invalid JSON -> fallback to empty object
	s = rawSchema(`{bad json`)
	if m, ok := s.(map[string]any); !ok || m["type"] != "object" {
		t.Errorf("rawSchema fallback failed: %v", s)
	}
}

// TestMCPToolLogic_RealAPI exercises the underlying cpe-skills API that the
// MCP tool handlers call, ensuring the wiring matches expected behavior.
func TestMCPToolLogic_RealAPI(t *testing.T) {
	ctx := context.Background()
	_ = ctx

	// match_cpe: identical CPEs match
	criteria, _ := parseCPEString("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	target, _ := parseCPEString("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	result := cpeskills.MatchCPE(criteria, target, &cpeskills.MatchOptions{
		AllowSubVersions: true,
	})
	if !result {
		t.Error("expected match=true for identical CPEs")
	}

	// compare_versions: 2.14.1 < 2.15.0
	cmp := cpeskills.CompareVersions("2.14.1", "2.15.0")
	if cmp >= 0 {
		t.Errorf("expected negative comparison, got %d", cmp)
	}
	if comparisonMeaning(cmp) != "a < b" {
		t.Errorf("meaning mismatch for %d", cmp)
	}

	// generate_cpe: produces valid 2.3 string with expected components
	c := cpeskills.GenerateCPE("a", "apache", "log4j", "2.14.1")
	if c == nil {
		t.Fatal("GenerateCPE returned nil")
	}
	if c.Vendor != "apache" || c.ProductName != "log4j" || c.Version != "2.14.1" {
		t.Errorf("generated CPE components wrong: vendor=%q product=%q version=%q",
			c.Vendor, c.ProductName, c.Version)
	}
	if !strings.HasPrefix(cpeskills.FormatCpe23(c), "cpe:2.3:a:apache:log4j:") {
		t.Errorf("generated 2.3 string unexpected: %s", cpeskills.FormatCpe23(c))
	}

	// validate_cpe: valid CPE passes
	if err := cpeskills.ValidateCPE(c); err != nil {
		t.Errorf("ValidateCPE on generated CPE failed: %v", err)
	}

	// in_range
	if !cpeskills.IsVersionInRange("2.14.1", "2.0", "3.0") {
		t.Error("expected 2.14.1 in [2.0, 3.0]")
	}
}
