package cpeskills

import (
	"testing"
)

func TestMustParse(t *testing.T) {
	cpe := MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if cpe == nil {
		t.Fatal("MustParse() returned nil")
	}
	if string(cpe.Vendor) != "microsoft" {
		t.Errorf("MustParse() Vendor = %q, want microsoft", cpe.Vendor)
	}
}

func TestMustParse_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("MustParse() should panic on invalid input")
		}
	}()
	MustParse("invalid")
}

func TestParseOr_Valid(t *testing.T) {
	defaultCPE := &CPE{Cpe23: "default"}
	result := ParseOr("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", defaultCPE)
	if string(result.Vendor) != "microsoft" {
		t.Errorf("ParseOr() Vendor = %q, want microsoft", result.Vendor)
	}
}

func TestParseOr_Invalid(t *testing.T) {
	defaultCPE := &CPE{Cpe23: "default"}
	result := ParseOr("invalid", defaultCPE)
	if result != defaultCPE {
		t.Error("ParseOr() should return default for invalid input")
	}
}

func TestIsCPE23String(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", true},
		{"cpe:/a:microsoft:windows:10", false},
		{"not a cpe", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsCPE23String(tt.input); got != tt.expected {
			t.Errorf("IsCPE23String(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestIsCPE22String(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"cpe:/a:microsoft:windows:10", true},
		{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", false},
		{"not a cpe", false},
	}
	for _, tt := range tests {
		if got := IsCPE22String(tt.input); got != tt.expected {
			t.Errorf("IsCPE22String(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestQuickMatch(t *testing.T) {
	matched, err := QuickMatch(
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
	)
	if err != nil {
		t.Errorf("QuickMatch() error = %v", err)
	}
	if !matched {
		t.Error("QuickMatch() should match identical CPEs")
	}
}

func TestQuickMatch_InvalidFirst(t *testing.T) {
	_, err := QuickMatch("invalid", "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err == nil {
		t.Error("QuickMatch() should return error for invalid first CPE")
	}
}

func TestQuickMatch_InvalidSecond(t *testing.T) {
	_, err := QuickMatch("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", "invalid")
	if err == nil {
		t.Error("QuickMatch() should return error for invalid second CPE")
	}
}

func TestStringToPart(t *testing.T) {
	tests := []struct {
		input     string
		shortName string
		hasError  bool
	}{
		{"a", "a", false},
		{"A", "a", false},
		{"application", "a", false},
		{"h", "h", false},
		{"hardware", "h", false},
		{"o", "o", false},
		{"os", "o", false},
		{"x", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		part, err := StringToPart(tt.input)
		if tt.hasError {
			if err == nil {
				t.Errorf("StringToPart(%q) should return error", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("StringToPart(%q) error = %v", tt.input, err)
			}
			if string(part.ShortName) != tt.shortName {
				t.Errorf("StringToPart(%q) ShortName = %q, want %q", tt.input, part.ShortName, tt.shortName)
			}
		}
	}
}

func TestFormatCPE(t *testing.T) {
	cpe := MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")

	str23, err := FormatCPE(cpe, "2.3")
	if err != nil {
		t.Errorf("FormatCPE() 2.3 error = %v", err)
	}
	if !IsCPE23String(str23) {
		t.Errorf("FormatCPE() 2.3 = %q, want CPE 2.3 format", str23)
	}

	str22, err := FormatCPE(cpe, "2.2")
	if err != nil {
		t.Errorf("FormatCPE() 2.2 error = %v", err)
	}
	if !IsCPE22String(str22) {
		t.Errorf("FormatCPE() 2.2 = %q, want CPE 2.2 format", str22)
	}

	_, err = FormatCPE(cpe, "3.0")
	if err == nil {
		t.Error("FormatCPE() should return error for unsupported version")
	}

	_, err = FormatCPE(nil, "2.3")
	if err == nil {
		t.Error("FormatCPE() should return error for nil CPE")
	}
}

func TestClone(t *testing.T) {
	original := MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	cloned := Clone(original)

	if cloned == nil {
		t.Fatal("Clone() returned nil")
	}
	if cloned.Cpe23 != original.Cpe23 {
		t.Errorf("Clone() Cpe23 = %q, want %q", cloned.Cpe23, original.Cpe23)
	}

	cloned.Vendor = Vendor("modified")
	if original.Vendor == Vendor("modified") {
		t.Error("Clone() should return a deep copy")
	}

	if Clone(nil) != nil {
		t.Error("Clone(nil) should return nil")
	}
}

func TestCPEsToStrings(t *testing.T) {
	cpes := []*CPE{
		MustParse("cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*"),
		MustParse("cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*"),
		nil,
	}
	strs := CPEsToStrings(cpes)
	if len(strs) != 2 {
		t.Errorf("CPEsToStrings() returned %d strings, want 2", len(strs))
	}
}

func TestStringsToCPEs(t *testing.T) {
	strs := []string{
		"cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		"invalid",
		"cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
	}
	cpes := StringsToCPEs(strs)
	if len(cpes) != 2 {
		t.Errorf("StringsToCPEs() returned %d CPEs, want 2", len(cpes))
	}
}

func TestFilterByPart(t *testing.T) {
	cpes := []*CPE{
		{Cpe23: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", Part: *PartApplication},
		{Cpe23: "cpe:2.3:h:vendor:device:1.0:*:*:*:*:*:*:*", Part: *PartHardware},
		{Cpe23: "cpe:2.3:o:vendor:os:1.0:*:*:*:*:*:*:*", Part: *PartOperationSystem},
	}
	apps := FilterByPart(cpes, PartApplication)
	if len(apps) != 1 {
		t.Errorf("FilterByPart() returned %d, want 1", len(apps))
	}
}

func TestFilterByVendor(t *testing.T) {
	cpes := []*CPE{
		{Cpe23: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", Vendor: Vendor("microsoft")},
		{Cpe23: "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", Vendor: Vendor("apache")},
	}
	msCPEs := FilterByVendor(cpes, "microsoft")
	if len(msCPEs) != 1 {
		t.Errorf("FilterByVendor() returned %d, want 1", len(msCPEs))
	}
}

func TestFilterByProduct(t *testing.T) {
	cpes := []*CPE{
		{Cpe23: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", ProductName: Product("windows")},
		{Cpe23: "cpe:2.3:a:microsoft:office:2021:*:*:*:*:*:*:*", ProductName: Product("office")},
	}
	winCPEs := FilterByProduct(cpes, "windows")
	if len(winCPEs) != 1 {
		t.Errorf("FilterByProduct() returned %d, want 1", len(winCPEs))
	}
}

func TestGetPartName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"a", "Application"},
		{"A", "Application"},
		{"h", "Hardware"},
		{"H", "Hardware"},
		{"o", "Operating System"},
		{"O", "Operating System"},
		{"x", "Unknown"},
	}
	for _, tt := range tests {
		if got := GetPartName(tt.input); got != tt.expected {
			t.Errorf("GetPartName(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
