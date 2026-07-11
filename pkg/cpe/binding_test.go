package cpeskills

import (
	"testing"
)

func TestBindToFS(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected string
	}{
		{
			name:     "nil WFN",
			wfn:      nil,
			expected: "",
		},
		{
			name: "simple WFN",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name: "WFN with special chars",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "example.com",
				Product: "product:name",
				Version: "1.0",
			},
			expected: "cpe:2.3:a:example\\.com:product%3aname:1\\.0:*:*:*:*:*:*:*",
		},
		{
			name: "full WFN",
			wfn: &WFN{
				Part:            "a",
				Vendor:          "apache",
				Product:         "tomcat",
				Version:         "8.5.0",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			expected: "cpe:2.3:a:apache:tomcat:8\\.5\\.0:sp1:pro:en:enterprise:linux:x86:custom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BindToFS(tt.wfn); got != tt.expected {
				t.Errorf("BindToFS() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestUnbindFS(t *testing.T) {
	tests := []struct {
		name    string
		fs      string
		wantErr bool
		part    string
		vendor  string
		product string
		version string
	}{
		{
			name:    "valid FS",
			fs:      "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
		},
		{
			name:    "invalid prefix",
			fs:      "cpe:2.2:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "wrong part count",
			fs:      "cpe:2.3:a:microsoft:windows",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wfn, err := UnbindFS(tt.fs)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnbindFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if wfn.Part != tt.part {
					t.Errorf("UnbindFS().Part = %v, want %v", wfn.Part, tt.part)
				}
				if wfn.Vendor != tt.vendor {
					t.Errorf("UnbindFS().Vendor = %v, want %v", wfn.Vendor, tt.vendor)
				}
				if wfn.Product != tt.product {
					t.Errorf("UnbindFS().Product = %v, want %v", wfn.Product, tt.product)
				}
				if wfn.Version != tt.version {
					t.Errorf("UnbindFS().Version = %v, want %v", wfn.Version, tt.version)
				}
			}
		})
	}
}

func TestBindToURI(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected string
	}{
		{
			name:     "nil WFN",
			wfn:      nil,
			expected: "",
		},
		{
			name: "simple WFN",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: "cpe:/a:microsoft:windows:10:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BindToURI(tt.wfn); got != tt.expected {
				t.Errorf("BindToURI() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConvertURIToFS(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
		wantErr  bool
	}{
		{
			name:     "basic conversion",
			uri:      "cpe:/a:microsoft:windows:10",
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr:  false,
		},
		{
			name:    "invalid URI",
			uri:     "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertURIToFS(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertURIToFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ConvertURIToFS() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestConvertFSToURI(t *testing.T) {
	tests := []struct {
		name    string
		fs      string
		wantErr bool
	}{
		{
			name:    "valid conversion",
			fs:      "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
		},
		{
			name:    "invalid FS",
			fs:      "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConvertFSToURI(tt.fs)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertFSToURI() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConvertCpe22ToCpe23Binding(t *testing.T) {
	tests := []struct {
		name     string
		cpe22    string
		expected string
	}{
		{
			name:     "basic conversion",
			cpe22:    "cpe:/a:microsoft:windows:10",
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name:     "invalid format",
			cpe22:    "invalid",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertCpe22ToCpe23(tt.cpe22); got != tt.expected {
				t.Errorf("convertCpe22ToCpe23() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBindToURIExtended(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected string
	}{
		{
			name: "WFN with extended attributes",
			wfn: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			expected: "cpe:/a:microsoft:windows:10:*:pro~en~enterprise~linux~x86~custom",
		},
		{
			name: "WFN with only language",
			wfn: &WFN{
				Part:     "a",
				Vendor:   "microsoft",
				Product:  "windows",
				Version:  "10",
				Language: "en",
			},
			expected: "cpe:/a:microsoft:windows:10:*:~en",
		},
		{
			name: "WFN with special characters",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "example.com",
				Product: "product:name",
				Version: "1.0",
			},
			expected: "cpe:/a:example%2ecom:product%3aname:1%2e0:*",
		},
		{
			name: "WFN with NA update",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
				Update:  ValueNA,
			},
			expected: "cpe:/a:microsoft:windows:10:-",
		},
		{
			name: "WFN with all ANY (no extended)",
			wfn: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: "cpe:/a:microsoft:windows:10:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BindToURI(tt.wfn); got != tt.expected {
				t.Errorf("BindToURI() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestUnbindURIExtended(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
		part    string
		vendor  string
		product string
		version string
		update  string
	}{
		{
			name:    "basic URI",
			uri:     "cpe:/a:microsoft:windows:10",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
		},
		{
			name:    "URI with update",
			uri:     "cpe:/a:microsoft:windows:10:sp1",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
			update:  "sp1",
		},
		{
			name:    "URI with extended attributes (tilde format)",
			uri:     "cpe:/a:microsoft:windows:10:sp1:pro~~en~enterprise~linux~x86~custom",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
			update:  "sp1",
		},
		{
			name:    "URI with percent-encoded values",
			uri:     "cpe:/a:example%2ecom:product%3aname:1%2e0",
			wantErr: false,
			part:    "a",
			vendor:  "example.com",
			product: "product:name",
			version: "1.0",
		},
		{
			name:    "invalid prefix",
			uri:     "invalid-uri",
			wantErr: true,
		},
		{
			name:    "empty content",
			uri:     "cpe:/",
			wantErr: true,
		},
		{
			name:    "URI with edition only (no tilde)",
			uri:     "cpe:/a:microsoft:windows:10:*:pro",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
		},
		{
			name:    "URI with edition and language (no tilde)",
			uri:     "cpe:/a:microsoft:windows:10:*:pro:en",
			wantErr: false,
			part:    "a",
			vendor:  "microsoft",
			product: "windows",
			version: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wfn, err := UnbindURI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnbindURI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if wfn.Part != tt.part {
					t.Errorf("UnbindURI().Part = %q, want %q", wfn.Part, tt.part)
				}
				if wfn.Vendor != tt.vendor {
					t.Errorf("UnbindURI().Vendor = %q, want %q", wfn.Vendor, tt.vendor)
				}
				if wfn.Product != tt.product {
					t.Errorf("UnbindURI().Product = %q, want %q", wfn.Product, tt.product)
				}
				if wfn.Version != tt.version {
					t.Errorf("UnbindURI().Version = %q, want %q", wfn.Version, tt.version)
				}
				if tt.update != "" && wfn.Update != tt.update {
					t.Errorf("UnbindURI().Update = %q, want %q", wfn.Update, tt.update)
				}
			}
		})
	}
}

func TestUnbindURIWithExtendedAttributes(t *testing.T) {
	// Test UnbindURI with extended attributes in tilde format
	// The tilde-separated part at index 5 is split by "~":
	// extParts[0]=edition, extParts[3]=language, extParts[4]=sw_edition,
	// extParts[5]=target_sw, extParts[6]=target_hw, extParts[7]=other
	// Format: cpe:/part:vendor:product:version:update:~[sw_edition]~[target_sw]~[target_hw]~[other]
	wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:~~~~enterprise~~")
	if err != nil {
		t.Fatalf("UnbindURI() error = %v", err)
	}
	if wfn.Part != "a" {
		t.Errorf("Part = %q, want %q", wfn.Part, "a")
	}
	if wfn.Vendor != "vendor" {
		t.Errorf("Vendor = %q, want %q", wfn.Vendor, "vendor")
	}
	if wfn.Product != "product" {
		t.Errorf("Product = %q, want %q", wfn.Product, "product")
	}
	if wfn.Version != "1.0" {
		t.Errorf("Version = %q, want %q", wfn.Version, "1.0")
	}
	if wfn.SoftwareEdition != "enterprise" {
		t.Errorf("SoftwareEdition = %q, want %q", wfn.SoftwareEdition, "enterprise")
	}
}

func TestBindAttributeValueToFS(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"ANY value", ValueANY, ValueANY},
		{"NA value", ValueNA, ValueNA},
		{"empty string", "", ValueANY},
		{"simple value", "windows", "windows"},
		{"dot value", "example.com", "example\\.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindAttributeValueToFS(tt.value); got != tt.expected {
				t.Errorf("bindAttributeValueToFS(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnbindFSComponent(t *testing.T) {
	tests := []struct {
		name     string
		component string
		expected  string
	}{
		{"ANY value", ValueANY, ValueANY},
		{"NA value", ValueNA, ValueNA},
		{"empty string", "", ValueANY},
		{"simple value", "windows", "windows"},
		{"escaped dot", `example\.com`, "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unbindFSComponent(tt.component); got != tt.expected {
				t.Errorf("unbindFSComponent(%q) = %q, want %q", tt.component, got, tt.expected)
			}
		})
	}
}

func TestBindAttributeValueToURI(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"ANY value", ValueANY, ValueANY},
		{"NA value", ValueNA, ValueNA},
		{"empty string", "", ValueANY},
		{"simple value", "windows", "windows"},
		{"dot value", "example.com", "example%2ecom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bindAttributeValueToURI(tt.value); got != tt.expected {
				t.Errorf("bindAttributeValueToURI(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnbindURIComponent(t *testing.T) {
	tests := []struct {
		name      string
		component string
		expected  string
	}{
		{"ANY value", ValueANY, ValueANY},
		{"NA value", ValueNA, ValueNA},
		{"empty string", "", ValueANY},
		{"simple value", "windows", "windows"},
		{"percent-encoded", "example%2ecom", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unbindURIComponent(tt.component); got != tt.expected {
				t.Errorf("unbindURIComponent(%q) = %q, want %q", tt.component, got, tt.expected)
			}
		})
	}
}

// TestUnbindURI_WithOtherField tests that UnbindURI correctly parses the Other field from extended format
func TestUnbindURI_WithOtherField(t *testing.T) {
	// CPE URI with extended format containing Other field (7th extension part)
	// Format: edition~blank~blank~language~sw_ed~target_sw~target_hw~other
	uri := "cpe:/a:vendor:product:1.0:update:edition~~~language~sw_ed~target_sw~target_hw~other_val"
	result, err := UnbindURI(uri)
	if err != nil {
		t.Fatalf("UnbindURI() error = %v", err)
	}
	if result.Other != "other_val" {
		t.Errorf("UnbindURI() Other = %q, want %q", result.Other, "other_val")
	}
}

	// TestUnbindURI_CoverageGap_SoftwareEdition tests UnbindURI parsing sw_edition from extended tilde format
	// Format: extParts[0]=edition, [1]=blank, [2]=blank, [3]=language, [4]=sw_edition, [5]=target_sw, [6]=target_hw, [7]=other
	func TestUnbindURI_CoverageGap_SoftwareEdition(t *testing.T) {
		// ~~~en~enterprise~~ => ["","","","en","enterprise","",""] => language at idx3, sw_edition at idx4
		wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:~~~en~enterprise~~")
		if err != nil {
			t.Fatalf("UnbindURI() error = %v", err)
		}
		if wfn.Language != "en" {
			t.Errorf("Language = %q, want %q", wfn.Language, "en")
		}
		if wfn.SoftwareEdition != "enterprise" {
			t.Errorf("SoftwareEdition = %q, want %q", wfn.SoftwareEdition, "enterprise")
		}
	}

	// TestUnbindURI_CoverageGap_TargetSoftware tests UnbindURI parsing target_sw from extended tilde format
	func TestUnbindURI_CoverageGap_TargetSoftware(t *testing.T) {
		// ~~~~~linux~~ => ["","","","","","linux","",""] => target_sw at idx5
		wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:~~~~~linux~~")
		if err != nil {
			t.Fatalf("UnbindURI() error = %v", err)
		}
		if wfn.TargetSoftware != "linux" {
			t.Errorf("TargetSoftware = %q, want %q", wfn.TargetSoftware, "linux")
		}
	}

	// TestUnbindURI_CoverageGap_TargetHardware tests UnbindURI parsing target_hw from extended tilde format
	func TestUnbindURI_CoverageGap_TargetHardware(t *testing.T) {
		// ~~~~~~x86~ => ["","","","","","","x86",""] => target_hw at idx6
		wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:~~~~~~x86~")
		if err != nil {
			t.Fatalf("UnbindURI() error = %v", err)
		}
		if wfn.TargetHardware != "x86" {
			t.Errorf("TargetHardware = %q, want %q", wfn.TargetHardware, "x86")
		}
	}

	// TestUnbindURI_CoverageGap_Other tests UnbindURI parsing other from extended tilde format
	func TestUnbindURI_CoverageGap_Other(t *testing.T) {
		// ~~~~~~~custom => ["","","","","","","","custom"] => other at idx7
		wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:~~~~~~~custom")
		if err != nil {
			t.Fatalf("UnbindURI() error = %v", err)
		}
		if wfn.Other != "custom" {
			t.Errorf("Other = %q, want %q", wfn.Other, "custom")
		}
	}

	// TestUnbindURI_CoverageGap_EditionInTilde tests UnbindURI parsing edition from tilde at index 5
	func TestUnbindURI_CoverageGap_EditionInTilde(t *testing.T) {
		// professional~~~~~~~ => ["professional","","","","","","",""] => edition at idx0
		wfn, err := UnbindURI("cpe:/a:vendor:product:1.0:*:professional~~~~~~~")
		if err != nil {
			t.Fatalf("UnbindURI() error = %v", err)
		}
		if wfn.Edition != "professional" {
			t.Errorf("Edition = %q, want %q", wfn.Edition, "professional")
		}
	}
