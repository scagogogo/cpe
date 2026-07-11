package cpeskills

import "testing"

// TestFormatCpe23_EmptyFields tests FormatCpe23 with empty vendor, product, and version
func TestFormatCpe23_EmptyFields(t *testing.T) {
	cpe := &CPE{
		Part: *PartApplication,
	}
	result := FormatCpe23(cpe)
	if result == "" {
		t.Error("FormatCpe23() with empty fields should return non-empty string")
	}
	// Should use * for empty fields
	expected := "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"
	if result != expected {
		t.Errorf("FormatCpe23() with empty fields = %q, want %q", result, expected)
	}
}
