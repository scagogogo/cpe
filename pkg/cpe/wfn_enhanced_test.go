package cpeskills

import (
	"testing"
)

func TestNewWFN(t *testing.T) {
	wfn := NewWFN()
	if wfn == nil {
		t.Fatal("NewWFN() returned nil")
	}

	// All attributes should default to ANY via Get
	if wfn.Get(AttrPart) != ValueANY {
		t.Errorf("NewWFN().Get(AttrPart) = %q, want %q", wfn.Get(AttrPart), ValueANY)
	}
	if wfn.Get(AttrVendor) != ValueANY {
		t.Errorf("NewWFN().Get(AttrVendor) = %q, want %q", wfn.Get(AttrVendor), ValueANY)
	}
}

func TestWFNGet(t *testing.T) {
	wfn := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "", // empty should return ANY
	}

	tests := []struct {
		attr     string
		expected string
	}{
		{AttrPart, "a"},
		{AttrVendor, "microsoft"},
		{AttrProduct, "windows"},
		{AttrVersion, ValueANY}, // empty defaults to ANY
		{AttrUpdate, ValueANY},  // not set, defaults to ANY
		{"invalid_attr", ValueANY},
	}

	for _, tt := range tests {
		t.Run(tt.attr, func(t *testing.T) {
			if got := wfn.Get(tt.attr); got != tt.expected {
				t.Errorf("WFN.Get(%q) = %q, want %q", tt.attr, got, tt.expected)
			}
		})
	}
}

func TestWFNSet(t *testing.T) {
	wfn := NewWFN()

	wfn.Set(AttrPart, "a")
	wfn.Set(AttrVendor, "microsoft")
	wfn.Set(AttrProduct, "windows")
	wfn.Set(AttrVersion, "10")

	if wfn.Part != "a" {
		t.Errorf("Part = %q, want %q", wfn.Part, "a")
	}
	if wfn.Vendor != "microsoft" {
		t.Errorf("Vendor = %q, want %q", wfn.Vendor, "microsoft")
	}
	if wfn.Product != "windows" {
		t.Errorf("Product = %q, want %q", wfn.Product, "windows")
	}
	if wfn.Version != "10" {
		t.Errorf("Version = %q, want %q", wfn.Version, "10")
	}

	// Setting unknown attribute should be no-op
	wfn.Set("unknown_attr", "value")
	// Should not panic
}

func TestWFNString(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected string
	}{
		{
			name:     "empty WFN",
			wfn:      NewWFN(),
			expected: "wfn:[]",
		},
		{
			name: "partial WFN",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
			},
			expected: `wfn:[part="a",vendor="microsoft",product="windows"]`,
		},
		{
			name: "full WFN",
			wfn: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			expected: `wfn:[part="a",vendor="microsoft",product="windows",version="10",update="sp1",edition="pro",language="en",sw_edition="enterprise",target_sw="linux",target_hw="x86",other="custom"]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wfn.WFNString(); got != tt.expected {
				t.Errorf("WFNString() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIsIdentifierName(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected bool
	}{
		{
			name: "valid identifier",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: true,
		},
		{
			name: "ANY part - not identifier",
			wfn: &WFN{
				Part:    ValueANY,
				Vendor:  "microsoft",
				Product: "windows",
			},
			expected: false,
		},
		{
			name: "ANY vendor - not identifier",
			wfn: &WFN{
				Part:    "a",
				Vendor:  ValueANY,
				Product: "windows",
			},
			expected: false,
		},
		{
			name: "ANY product - not identifier",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: ValueANY,
			},
			expected: false,
		},
		{
			name: "NA part - not identifier",
			wfn: &WFN{
				Part:    ValueNA,
				Vendor:  "microsoft",
				Product: "windows",
			},
			expected: false,
		},
		{
			name: "wildcard in version - not identifier",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "1*",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wfn.IsIdentifierName(); got != tt.expected {
				t.Errorf("IsIdentifierName() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDefaultToANY(t *testing.T) {
	wfn := NewWFN()

	if wfn.defaultToANY("") != ValueANY {
		t.Errorf("defaultToANY('') = %q, want %q", wfn.defaultToANY(""), ValueANY)
	}
	if wfn.defaultToANY("windows") != "windows" {
		t.Errorf("defaultToANY('windows') = %q, want %q", wfn.defaultToANY("windows"), "windows")
	}
}

func TestWFNConstants(t *testing.T) {
	if ValueANY != "*" {
		t.Errorf("ValueANY = %q, want %q", ValueANY, "*")
	}
	if ValueNA != "-" {
		t.Errorf("ValueNA = %q, want %q", ValueNA, "-")
	}

	if AttrPart != "part" {
		t.Errorf("AttrPart = %q, want %q", AttrPart, "part")
	}
	if AttrVendor != "vendor" {
		t.Errorf("AttrVendor = %q, want %q", AttrVendor, "vendor")
	}

	if PartApplicationShort != "a" {
		t.Errorf("PartApplicationShort = %q, want %q", PartApplicationShort, "a")
	}
	if PartOSShort != "o" {
		t.Errorf("PartOSShort = %q, want %q", PartOSShort, "o")
	}
	if PartHardwareShort != "h" {
		t.Errorf("PartHardwareShort = %q, want %q", PartHardwareShort, "h")
	}
}

func TestValidPartValues(t *testing.T) {
	if !ValidPartValues["a"] {
		t.Error("ValidPartValues should contain 'a'")
	}
	if !ValidPartValues["o"] {
		t.Error("ValidPartValues should contain 'o'")
	}
	if !ValidPartValues["h"] {
		t.Error("ValidPartValues should contain 'h'")
	}
	if !ValidPartValues[ValueANY] {
		t.Error("ValidPartValues should contain '*'")
	}
	if ValidPartValues["x"] {
		t.Error("ValidPartValues should not contain 'x'")
	}
}

func TestAllAttributes(t *testing.T) {
	expected := []string{
		AttrPart, AttrVendor, AttrProduct, AttrVersion, AttrUpdate,
		AttrEdition, AttrLanguage, AttrSoftwareEdition, AttrTargetSoftware,
		AttrTargetHardware, AttrOther,
	}

	if len(allAttributes) != len(expected) {
		t.Errorf("allAttributes length = %d, want %d", len(allAttributes), len(expected))
	}

	for i, attr := range allAttributes {
		if attr != expected[i] {
			t.Errorf("allAttributes[%d] = %q, want %q", i, attr, expected[i])
		}
	}
}

func TestFromCPE22String(t *testing.T) {
	tests := []struct {
		name    string
		cpe22   string
		wantErr bool
		part    string
		vendor  string
		product string
		version string
	}{
		{
			name:    "valid CPE 2.2",
			cpe22:   "cpe:/a:microsoft:windows:10",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
		},
		{
			name:    "invalid CPE 2.2",
			cpe22:   "not-a-cpe",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wfn, err := FromCPE22String(tt.cpe22)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromCPE22String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if wfn.Part != tt.part {
					t.Errorf("Part = %q, want %q", wfn.Part, tt.part)
				}
				if wfn.Vendor != tt.vendor {
					t.Errorf("Vendor = %q, want %q", wfn.Vendor, tt.vendor)
				}
				if wfn.Product != tt.product {
					t.Errorf("Product = %q, want %q", wfn.Product, tt.product)
				}
				if wfn.Version != tt.version {
					t.Errorf("Version = %q, want %q", wfn.Version, tt.version)
				}
			}
		})
	}
}

func TestToCPE22String(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected string
	}{
		{
			name: "basic WFN - update defaults to empty (not ANY)",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: "cpe:/a:microsoft:windows:10:",
		},
		{
			name: "WFN with update set to ANY",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
				Update:  ValueANY,
			},
			expected: "cpe:/a:microsoft:windows:10:*",
		},
		{
			name: "WFN with edition and language",
			wfn: &WFN{
				Part:     "a",
				Vendor:   "microsoft",
				Product:  "windows",
				Version:  "10",
				Update:   "sp1",
				Edition:  "pro",
				Language: "en",
			},
			expected: "cpe:/a:microsoft:windows:10:sp1:pro~~~en",
		},
		{
			name: "WFN with all extended attributes",
			wfn: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			expected: "cpe:/a:microsoft:windows:10:sp1:pro~~~en~enterprise~linux~x86~custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wfn.ToCPE22String(); got != tt.expected {
				t.Errorf("ToCPE22String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestWFNMatchExtended(t *testing.T) {
	// Test with NA values
	wfn1 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "-",
	}
	wfn2 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "-",
	}
	if !wfn1.Match(wfn2) {
		t.Error("Expected NA versions to match")
	}

	// Test with different NA values
	wfn3 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "-",
	}
	wfn4 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
	}
	if wfn3.Match(wfn4) {
		t.Error("Expected NA and specific version not to match")
	}

	// Test with extended attributes
	wfn5 := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86",
		Other:           "custom",
	}
	wfn6 := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86",
		Other:           "custom",
	}
	if !wfn5.Match(wfn6) {
		t.Error("Expected identical WFNs with all attributes to match")
	}
}

func TestIsIdentifierNameExtended(t *testing.T) {
	// NA vendor
	wfn := &WFN{
		Part:    "a",
		Vendor:  ValueNA,
		Product: "windows",
	}
	if wfn.IsIdentifierName() {
		t.Error("NA vendor should not be identifier name")
	}

	// NA product
	wfn = &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: ValueNA,
	}
	if wfn.IsIdentifierName() {
		t.Error("NA product should not be identifier name")
	}

	// wildcard in vendor
	wfn = &WFN{
		Part:    "a",
		Vendor:  "micro*",
		Product: "windows",
	}
	if wfn.IsIdentifierName() {
		t.Error("Wildcard in vendor should not be identifier name")
	}

	// wildcard in other attribute
	wfn = &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "1?",
	}
	if wfn.IsIdentifierName() {
		t.Error("Wildcard in version should not be identifier name")
	}

	// All set with no wildcards
	wfn = &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86",
		Other:           "custom",
	}
	if !wfn.IsIdentifierName() {
		t.Error("Fully specified WFN should be identifier name")
	}
}

func TestWFNStringWithQuotes(t *testing.T) {
	// Test WFNString with values that contain quotes
	wfn := &WFN{
		Part:    "a",
		Vendor:  `value"with"quotes`,
		Product: "windows",
	}
	result := wfn.WFNString()
	// quoteForWFN escapes " to \"
	expected := `wfn:[part="a",vendor="value\"with\"quotes",product="windows"]`
	if result != expected {
		t.Errorf("WFNString() = %q, want %q", result, expected)
	}
}
