package cpeskills

import (
	"bytes"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// ParseDictionary tests
// =============================================================================

func TestDictionary_ParseDictionary_Basic(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3" generated="2021-12-10T00:00:00Z">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.0</title>
  </cpe-item>
  <cpe-item name="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*">
    <title>Vendor Product 1.0</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dict == nil {
		t.Fatal("expected non-nil dictionary")
	}
	if dict.SchemaVersion != "2.3" {
		t.Errorf("expected SchemaVersion='2.3', got %q", dict.SchemaVersion)
	}
	if len(dict.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(dict.Items))
	}
	if dict.Items[0].Name != "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" {
		t.Errorf("expected first item name, got %q", dict.Items[0].Name)
	}
	if dict.Items[0].Title != "Apache Log4j 2.0" {
		t.Errorf("expected first item title, got %q", dict.Items[0].Title)
	}
}

func TestDictionary_ParseDictionary_WithCPE22(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.2" generated="2021-01-01T00:00:00Z">
  <cpe-item name="cpe:/a:apache:log4j:2.0">
    <title>Apache Log4j 2.0</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if dict.Items[0].CPE == nil {
		t.Error("expected CPE to be parsed from 2.2 format")
	}
}

func TestDictionary_ParseDictionary_WithCPE23(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.0</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if dict.Items[0].CPE == nil {
		t.Error("expected CPE to be parsed from 2.3 format")
	}
}

func TestDictionary_ParseDictionary_WithReferences(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.0</title>
    <references>
      <reference href="https://logging.apache.org/log4j/2.x/" type="Vendor"/>
      <reference href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" type="Advisory"/>
    </references>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if len(dict.Items[0].References) != 2 {
		t.Fatalf("expected 2 references, got %d", len(dict.Items[0].References))
	}
	if dict.Items[0].References[0].URL != "https://logging.apache.org/log4j/2.x/" {
		t.Errorf("expected first reference URL, got %q", dict.Items[0].References[0].URL)
	}
	if dict.Items[0].References[0].Type != "Vendor" {
		t.Errorf("expected first reference type 'Vendor', got %q", dict.Items[0].References[0].Type)
	}
	if dict.Items[0].References[1].Type != "Advisory" {
		t.Errorf("expected second reference type 'Advisory', got %q", dict.Items[0].References[1].Type)
	}
}

func TestDictionary_ParseDictionary_Deprecated(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:apache:log4j:1.2:*:*:*:*:*:*:*" deprecated="true" deprecation_date="2021-12-10T00:00:00Z">
    <title>Apache Log4j 1.2 (Deprecated)</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if !dict.Items[0].Deprecated {
		t.Error("expected item to be deprecated")
	}
	if dict.Items[0].DeprecationDate == nil {
		t.Error("expected deprecation date to be set")
	}
}

func TestDictionary_ParseDictionary_DeprecatedWithoutDate(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:apache:log4j:1.2:*:*:*:*:*:*:*" deprecated="true">
    <title>Apache Log4j 1.2 (Deprecated)</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dict.Items[0].Deprecated {
		t.Error("expected item to be deprecated")
	}
	if dict.Items[0].DeprecationDate != nil {
		t.Error("expected deprecation date to be nil when not provided")
	}
}

func TestDictionary_ParseDictionary_NotDeprecated(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.0</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dict.Items[0].Deprecated {
		t.Error("expected item to not be deprecated")
	}
}

func TestDictionary_ParseDictionary_InvalidXML(t *testing.T) {
	_, err := ParseDictionary(strings.NewReader("not xml at all"))
	if err == nil {
		t.Fatal("expected error for invalid XML")
	}
}

func TestDictionary_ParseDictionary_GeneratedAt(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3" generated="2021-12-10T10:30:00Z">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Test</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dict.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be parsed")
	}
	if dict.GeneratedAt.Year() != 2021 {
		t.Errorf("expected year 2021, got %d", dict.GeneratedAt.Year())
	}
}

func TestDictionary_ParseDictionary_InvalidGeneratedAt(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3" generated="not-a-date">
  <cpe-item name="cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*">
    <title>Test</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dict.GeneratedAt.IsZero() {
		t.Error("expected zero GeneratedAt for invalid date")
	}
}

func TestDictionary_ParseDictionary_EmptyGeneratedAt(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*">
    <title>Test</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dict.GeneratedAt.IsZero() {
		t.Error("expected zero GeneratedAt for empty date")
	}
}

func TestDictionary_ParseDictionary_InvalidDeprecationDate(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*" deprecated="true" deprecation_date="invalid-date">
    <title>Test</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dict.Items[0].Deprecated {
		t.Error("expected item to be deprecated")
	}
	if dict.Items[0].DeprecationDate != nil {
		t.Error("expected nil DeprecationDate for invalid date")
	}
}

func TestDictionary_ParseDictionary_InvalidCPEName(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="not-a-valid-cpe">
    <title>Invalid CPE</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	// CPE should be nil for invalid name
	if dict.Items[0].CPE != nil {
		t.Error("expected nil CPE for invalid name")
	}
}

func TestDictionary_ParseDictionary_NoReferences(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3">
  <cpe-item name="cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*">
    <title>Test</title>
  </cpe-item>
</cpe-list>`

	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(dict.Items[0].References) != 0 {
		t.Errorf("expected 0 references, got %d", len(dict.Items[0].References))
	}
}

// =============================================================================
// ExportDictionary tests
// =============================================================================

func TestDictionary_ExportDictionary_Basic(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
		Items: []*CPEItem{
			{
				Name:  "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
				Title: "Apache Log4j 2.0",
				References: []Reference{
					{URL: "https://logging.apache.org/log4j/2.x/", Type: "Vendor"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `<?xml version="1.0"`) {
		t.Error("expected XML header in output")
	}
	if !strings.Contains(output, "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*") {
		t.Error("expected CPE name in output")
	}
	if !strings.Contains(output, "Apache Log4j 2.0") {
		t.Error("expected title in output")
	}
}

func TestDictionary_ExportDictionary_DeprecatedItem(t *testing.T) {
	depDate := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items: []*CPEItem{
			{
				Name:            "cpe:2.3:a:old:product:1.0:*:*:*:*:*:*:*",
				Title:           "Old Product",
				Deprecated:      true,
				DeprecationDate: &depDate,
			},
		},
	}

	var buf bytes.Buffer
	err := ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `deprecated="true"`) {
		t.Error("expected deprecated attribute in output")
	}
	if !strings.Contains(output, depDate.Format(time.RFC3339)) {
		t.Error("expected deprecation date in output")
	}
}

func TestDictionary_ExportDictionary_DeprecatedWithoutDate(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items: []*CPEItem{
			{
				Name:       "cpe:2.3:a:old:product:1.0:*:*:*:*:*:*:*",
				Title:      "Old Product",
				Deprecated: true,
			},
		},
	}

	var buf bytes.Buffer
	err := ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `deprecated="true"`) {
		t.Error("expected deprecated attribute in output")
	}
}

func TestDictionary_ExportDictionary_WithReferences(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items: []*CPEItem{
			{
				Name:  "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Title: "Test Product",
				References: []Reference{
					{URL: "https://example.com", Type: "Vendor"},
					{URL: "https://advisory.example.com", Type: "Advisory"},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "https://example.com") {
		t.Error("expected reference URL in output")
	}
	if !strings.Contains(output, "Vendor") {
		t.Error("expected reference type in output")
	}
}

func TestDictionary_ExportDictionary_EmptyDictionary(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items:         []*CPEItem{},
	}

	var buf bytes.Buffer
	err := ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "cpe-list") {
		t.Error("expected cpe-list element in output")
	}
}

func TestDictionary_ExportDictionary_WriteError(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items:         []*CPEItem{},
	}

	// Use a writer that always fails
	errWriter := &errorWriter{}
	err := ExportDictionary(dict, errWriter)
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
}

func TestDictionary_ExportDictionary_EncodeError(t *testing.T) {
	dict := &CPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   time.Now(),
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*", Title: "Test"},
		},
	}

	// Use a writer that succeeds on first write (XML header) but fails on second (Encode)
	encodeErrWriter := &secondWriteErrorWriter{}
	err := ExportDictionary(dict, encodeErrWriter)
	if err == nil {
		t.Fatal("expected error from failing encoder")
	}
}

// errorWriter is a writer that always returns an error
type errorWriter struct{}

func (e *errorWriter) Write(p []byte) (n int, err error) {
	return 0, errors.New("write error")
}

// secondWriteErrorWriter succeeds on first write but fails on subsequent ones
type secondWriteErrorWriter struct {
	writeCount int
}

func (s *secondWriteErrorWriter) Write(p []byte) (n int, err error) {
	s.writeCount++
	if s.writeCount == 1 {
		return len(p), nil // First write (XML header) succeeds
	}
	return 0, errors.New("encode error")
}

// =============================================================================
// FindItemByName tests
// =============================================================================

func TestDictionary_FindItemByName_Found(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j 2.0"},
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", Title: "Product 1.0"},
		},
	}

	item := dict.FindItemByName("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	if item == nil {
		t.Fatal("expected to find item")
	}
	if item.Title != "Log4j 2.0" {
		t.Errorf("expected title 'Log4j 2.0', got %q", item.Title)
	}
}

func TestDictionary_FindItemByName_NotFound(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j 2.0"},
		},
	}

	item := dict.FindItemByName("cpe:2.3:a:nonexistent:product:1.0:*:*:*:*:*:*:*")
	if item != nil {
		t.Error("expected nil for non-existent name")
	}
}

func TestDictionary_FindItemByName_EmptyDictionary(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{},
	}

	item := dict.FindItemByName("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	if item != nil {
		t.Error("expected nil for empty dictionary")
	}
}

// =============================================================================
// FindItemsByCriteria tests
// =============================================================================

func TestDictionary_FindItemsByCriteria_MatchingItems(t *testing.T) {
	cpe1, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	cpe2, _ := ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")

	if cpe1 == nil || cpe2 == nil {
		t.Fatal("failed to parse test CPEs")
	}

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: cpe1.Cpe23, Title: "Log4j", CPE: cpe1},
			{Name: cpe2.Cpe23, Title: "Windows", CPE: cpe2},
		},
	}

	// Use exact matching criteria: same vendor, product, and version as one item
	criteria, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	if criteria == nil {
		t.Fatal("failed to parse criteria CPE")
	}
	options := &MatchOptions{}

	results := dict.FindItemsByCriteria(criteria, options)
	if len(results) < 1 {
		t.Fatalf("expected at least 1 matching item, got %d", len(results))
	}
}

func TestDictionary_FindItemsByCriteria_NoMatchingItems(t *testing.T) {
	cpe1, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: cpe1.Cpe23, Title: "Log4j", CPE: cpe1},
		},
	}

	criteria, _ := ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	options := &MatchOptions{}

	results := dict.FindItemsByCriteria(criteria, options)
	if len(results) != 0 {
		t.Errorf("expected 0 matching items, got %d", len(results))
	}
}

func TestDictionary_FindItemsByCriteria_NilCPE(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "invalid-cpe", Title: "No CPE", CPE: nil},
		},
	}

	criteria, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	options := &MatchOptions{}

	results := dict.FindItemsByCriteria(criteria, options)
	if len(results) != 0 {
		t.Errorf("expected 0 matching items for nil CPE, got %d", len(results))
	}
}

func TestDictionary_FindItemsByCriteria_EmptyDictionary(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{},
	}

	criteria, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	options := &MatchOptions{}

	results := dict.FindItemsByCriteria(criteria, options)
	if len(results) != 0 {
		t.Errorf("expected 0 matching items, got %d", len(results))
	}
}

// =============================================================================
// AddItem tests
// =============================================================================

func TestDictionary_AddItem_NewItem(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{},
	}

	item := &CPEItem{
		Name:  "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Title: "Apache Log4j 2.0",
	}

	dict.AddItem(item)

	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if dict.Items[0].Name != "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" {
		t.Errorf("expected item name, got %q", dict.Items[0].Name)
	}
}

func TestDictionary_AddItem_ReplaceExisting(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Old Title"},
		},
	}

	updatedItem := &CPEItem{
		Name:  "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Title: "New Title",
	}

	dict.AddItem(updatedItem)

	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item (replaced), got %d", len(dict.Items))
	}
	if dict.Items[0].Title != "New Title" {
		t.Errorf("expected title 'New Title', got %q", dict.Items[0].Title)
	}
}

func TestDictionary_AddItem_DifferentNames(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j"},
		},
	}

	newItem := &CPEItem{
		Name:  "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*",
		Title: "Tomcat",
	}

	dict.AddItem(newItem)

	if len(dict.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(dict.Items))
	}
}

// =============================================================================
// RemoveItem tests
// =============================================================================

func TestDictionary_RemoveItem_Found(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j"},
			{Name: "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*", Title: "Tomcat"},
		},
	}

	removed := dict.RemoveItem("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	if !removed {
		t.Error("expected removed=true")
	}
	if len(dict.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(dict.Items))
	}
	if dict.Items[0].Name != "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*" {
		t.Errorf("expected remaining item to be Tomcat, got %q", dict.Items[0].Name)
	}
}

func TestDictionary_RemoveItem_NotFound(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j"},
		},
	}

	removed := dict.RemoveItem("cpe:2.3:a:nonexistent:product:1.0:*:*:*:*:*:*:*")

	if removed {
		t.Error("expected removed=false for non-existent item")
	}
	if len(dict.Items) != 1 {
		t.Errorf("expected 1 item (unchanged), got %d", len(dict.Items))
	}
}

func TestDictionary_RemoveItem_EmptyDictionary(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{},
	}

	removed := dict.RemoveItem("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	if removed {
		t.Error("expected removed=false for empty dictionary")
	}
}

func TestDictionary_RemoveItem_RemoveLastItem(t *testing.T) {
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Title: "Log4j"},
		},
	}

	removed := dict.RemoveItem("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	if !removed {
		t.Error("expected removed=true")
	}
	if len(dict.Items) != 0 {
		t.Errorf("expected 0 items, got %d", len(dict.Items))
	}
}

// =============================================================================
// NewCPEItem tests
// =============================================================================

func TestDictionary_NewCPEItem_WithCPE23(t *testing.T) {
	cpe, _ := ParseCpe23("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	item := NewCPEItem(cpe, "Apache Log4j 2.0")

	if item == nil {
		t.Fatal("expected non-nil item")
	}
	if item.Name != "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" {
		t.Errorf("expected name from Cpe23, got %q", item.Name)
	}
	if item.Title != "Apache Log4j 2.0" {
		t.Errorf("expected title 'Apache Log4j 2.0', got %q", item.Title)
	}
	if item.CPE != cpe {
		t.Error("expected CPE to be set")
	}
}

func TestDictionary_NewCPEItem_WithoutCPE23(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	// Cpe23 is empty, so FormatCpe23 should be used

	item := NewCPEItem(cpe, "Apache Log4j 2.0")

	if item == nil {
		t.Fatal("expected non-nil item")
	}
	if item.Name == "" {
		t.Error("expected non-empty name from FormatCpe23")
	}
	if !strings.HasPrefix(item.Name, "cpe:2.3:a:apache:log4j") {
		t.Errorf("expected name to start with CPE format, got %q", item.Name)
	}
}

func TestDictionary_NewCPEItem_Title(t *testing.T) {
	cpe, _ := ParseCpe23("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

	item := NewCPEItem(cpe, "My Product Title")

	if item.Title != "My Product Title" {
		t.Errorf("expected title 'My Product Title', got %q", item.Title)
	}
}

// =============================================================================
// Round-trip: Parse then Export
// =============================================================================

func TestDictionary_RoundTrip_ParseAndExport(t *testing.T) {
	xmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<cpe-list schema_version="2.3" generated="2021-12-10T00:00:00Z">
  <cpe-item name="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*">
    <title>Apache Log4j 2.0</title>
    <references>
      <reference href="https://logging.apache.org/" type="Vendor"/>
    </references>
  </cpe-item>
  <cpe-item name="cpe:2.3:a:old:product:1.0:*:*:*:*:*:*:*" deprecated="true" deprecation_date="2021-12-10T00:00:00Z">
    <title>Old Product</title>
  </cpe-item>
</cpe-list>`

	// Parse
	dict, err := ParseDictionary(strings.NewReader(xmlContent))
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	// Export
	var buf bytes.Buffer
	err = ExportDictionary(dict, &buf)
	if err != nil {
		t.Fatalf("unexpected export error: %v", err)
	}

	// Parse again
	dict2, err := ParseDictionary(&buf)
	if err != nil {
		t.Fatalf("unexpected re-parse error: %v", err)
	}

	if len(dict2.Items) != 2 {
		t.Fatalf("expected 2 items in re-parsed dictionary, got %d", len(dict2.Items))
	}
	if dict2.Items[0].Name != "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" {
		t.Errorf("first item name mismatch: %q", dict2.Items[0].Name)
	}
	if !dict2.Items[1].Deprecated {
		t.Error("expected second item to be deprecated")
	}
}

// =============================================================================
// CPEItem struct tests
// =============================================================================

func TestDictionary_CPEItem_Fields(t *testing.T) {
	depDate := time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)
	item := &CPEItem{
		Name:            "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
		Title:           "Test Item",
		References:      []Reference{{URL: "https://example.com", Type: "Vendor"}},
		Deprecated:      true,
		DeprecationDate: &depDate,
	}

	if item.Name != "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*" {
		t.Errorf("unexpected Name: %q", item.Name)
	}
	if item.Title != "Test Item" {
		t.Errorf("unexpected Title: %q", item.Title)
	}
	if len(item.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(item.References))
	}
	if !item.Deprecated {
		t.Error("expected Deprecated=true")
	}
	if item.DeprecationDate == nil {
		t.Error("expected DeprecationDate to be set")
	}
}

// =============================================================================
// Reference struct test
// =============================================================================

func TestDictionary_Reference_Fields(t *testing.T) {
	ref := Reference{
		URL:  "https://example.com",
		Type: "Vendor",
	}

	if ref.URL != "https://example.com" {
		t.Errorf("expected URL, got %q", ref.URL)
	}
	if ref.Type != "Vendor" {
		t.Errorf("expected Type 'Vendor', got %q", ref.Type)
	}
}

// =============================================================================
// XMLCPEDictionary / XMLCPEItem / XMLReference struct tests
// =============================================================================

func TestDictionary_XMLStructs(t *testing.T) {
	// Test that the XML structs can be marshalled/unmarshalled correctly
	xmlRef := XMLReference{
		URL:  "https://example.com",
		Type: "Advisory",
	}

	xmlItem := XMLCPEItem{
		Name:            "cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*",
		Deprecated:      "true",
		DeprecationDate: "2021-12-10T00:00:00Z",
		Title:           "Test Item",
		References:      []XMLReference{xmlRef},
	}

	xmlDict := XMLCPEDictionary{
		SchemaVersion: "2.3",
		GeneratedAt:   "2021-12-10T00:00:00Z",
		Items:         []XMLCPEItem{xmlItem},
	}

	data, err := xml.Marshal(xmlDict)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var parsed XMLCPEDictionary
	err = xml.Unmarshal(data, &parsed)
	if err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if parsed.SchemaVersion != "2.3" {
		t.Errorf("expected SchemaVersion '2.3', got %q", parsed.SchemaVersion)
	}
	if len(parsed.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(parsed.Items))
	}
	if parsed.Items[0].Deprecated != "true" {
		t.Errorf("expected deprecated 'true', got %q", parsed.Items[0].Deprecated)
	}
}

// =============================================================================
// CPEDictionary struct test
// =============================================================================

func TestDictionary_CPEDictionary_Struct(t *testing.T) {
	now := time.Now()
	dict := &CPEDictionary{
		Items:         []*CPEItem{},
		GeneratedAt:   now,
		SchemaVersion: "2.3",
	}

	if dict.SchemaVersion != "2.3" {
		t.Errorf("expected SchemaVersion '2.3', got %q", dict.SchemaVersion)
	}
	if !dict.GeneratedAt.Equal(now) {
		t.Error("GeneratedAt mismatch")
	}
}

// Suppress unused import
var _ = xml.Header

// TestDictionary_FindItemsByCriteria_NilOptions 验证 options=nil 不 panic（用默认）。
// 回归测试：此前 matchCPE 解引用 nil options.UseRegex 导致 SIGSEGV。
func TestDictionary_FindItemsByCriteria_NilOptions(t *testing.T) {
	cpe, err := Parse("cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*", CPE: cpe, Title: "Apache Log4j 2.14"},
		},
	}
	// 不应 panic，且应命中。
	items := dict.FindItemsByCriteria(cpe, nil)
	if len(items) != 1 {
		t.Fatalf("expected 1 match with nil options, got %d", len(items))
	}
}
