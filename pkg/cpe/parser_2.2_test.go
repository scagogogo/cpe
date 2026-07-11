package cpeskills

import (
	"testing"
)

// TestParseCpe22 测试解析CPE 2.2格式字符串
func TestParseCpe22(t *testing.T) {
	tests := []struct {
		name     string
		cpeStr   string
		wantErr  bool
		expected *CPE
	}{
		{
			name:    "有效的CPE 2.2字符串",
			cpeStr:  "cpe:/a:microsoft:windows:10",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
		},
		{
			name:    "复杂的CPE 2.2字符串",
			cpeStr:  "cpe:/a:microsoft:windows:10:sp1:pro:en",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
				Edition:     "pro",
				Language:    "en",
			},
		},
		{
			name:    "带特殊字符的CPE 2.2字符串",
			cpeStr:  "cpe:/a:example%2ecom:product%3aname:1.0",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "example.com",
				ProductName: "product:name",
				Version:     "1.0",
			},
		},
		{
			name:    "无效的CPE 2.2格式",
			cpeStr:  "cpe:invalid",
			wantErr: true,
		},
		{
			name:    "非CPE字符串",
			cpeStr:  "not-a-cpe-string",
			wantErr: true,
		},
		{
			name:    "操作系统CPE",
			cpeStr:  "cpe:/o:linux:linux_kernel:5.10",
			wantErr: false,
			expected: &CPE{
				Part:        *PartOperationSystem,
				Vendor:      "linux",
				ProductName: "linux_kernel",
				Version:     "5.10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCpe22(tt.cpeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCpe22() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if got.Part.ShortName != tt.expected.Part.ShortName {
					t.Errorf("ParseCpe22() Part = %v, want %v", got.Part.ShortName, tt.expected.Part.ShortName)
				}
				if got.Vendor != tt.expected.Vendor {
					t.Errorf("ParseCpe22() Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
				}
				if got.ProductName != tt.expected.ProductName {
					t.Errorf("ParseCpe22() ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
				}
				if got.Version != tt.expected.Version {
					t.Errorf("ParseCpe22() Version = %v, want %v", got.Version, tt.expected.Version)
				}
				if tt.expected.Update != "" && got.Update != tt.expected.Update {
					t.Errorf("ParseCpe22() Update = %v, want %v", got.Update, tt.expected.Update)
				}
				if tt.expected.Edition != "" && got.Edition != tt.expected.Edition {
					t.Errorf("ParseCpe22() Edition = %v, want %v", got.Edition, tt.expected.Edition)
				}
				if tt.expected.Language != "" && got.Language != tt.expected.Language {
					t.Errorf("ParseCpe22() Language = %v, want %v", got.Language, tt.expected.Language)
				}
			}
		})
	}
}

// TestFormatCpe22 测试格式化CPE为2.2格式字符串
func TestFormatCpe22(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected string
	}{
		{
			name: "基本格式化",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: "cpe:/a:microsoft:windows:10",
		},
		{
			name: "带更多字段的格式化",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
				Edition:     "pro",
				Language:    "en",
			},
			expected: "cpe:/a:microsoft:windows:10:sp1:pro:en",
		},
		{
			name: "带特殊字符的格式化",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "example.com",
				ProductName: "product:name",
				Version:     "1.0",
			},
			expected: "cpe:/a:example%2ecom:product%3aname:1%2e0",
		},
		{
			name: "硬件格式化",
			cpe: &CPE{
				Part:        *PartHardware,
				Vendor:      "intel",
				ProductName: "core_i7",
				Version:     "1068g7",
			},
			expected: "cpe:/h:intel:core%5fi7:1068g7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCpe22(tt.cpe); got != tt.expected {
				t.Errorf("FormatCpe22() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestConvertCpe22ToCpe23 测试CPE 2.2格式转CPE 2.3格式
func TestConvertCpe22ToCpe23(t *testing.T) {
	tests := []struct {
		name     string
		cpe22    string
		expected string
	}{
		{
			name:     "基本转换",
			cpe22:    "cpe:/a:microsoft:windows:10",
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name:     "带更多字段的转换",
			cpe22:    "cpe:/a:microsoft:windows:10:sp1:pro:en",
			expected: "cpe:2.3:a:microsoft:windows:10:sp1:pro:en:*:*:*:*",
		},
		{
			name:     "带特殊字符的转换",
			cpe22:    "cpe:/a:example%2ecom:product%3aname:1.0",
			expected: "cpe:2.3:a:example\\.com:product%3aname:1\\.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertCpe22ToCpe23(tt.cpe22); got != tt.expected {
				t.Errorf("convertCpe22ToCpe23() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestEscapeCpe22Value 测试CPE 2.2值转义
func TestEscapeCpe22Value(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "普通值不需要转义",
			value:    "windows",
			expected: "windows",
		},
		{
			name:     "点需要转义",
			value:    "example.com",
			expected: "example%2ecom",
		},
		{
			name:     "冒号需要转义",
			value:    "product:name",
			expected: "product%3aname",
		},
		{
			name:     "斜杠需要转义",
			value:    "a/b",
			expected: "a%2fb",
		},
		{
			name:     "波浪号需要转义",
			value:    "version~rc1",
			expected: "version%7erc1",
		},
		{
			name:     "特殊值不需要转义",
			value:    "*",
			expected: "*",
		},
		{
			name:     "特殊值不需要转义",
			value:    "-",
			expected: "-",
		},
		{
			name:     "空值不需要转义",
			value:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeCpe22Value(tt.value); got != tt.expected {
				t.Errorf("escapeCpe22Value() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestParseCpe22Extended tests additional edge cases for ParseCpe22
func TestParseCpe22Extended(t *testing.T) {
	tests := []struct {
		name     string
		cpeStr   string
		wantErr  bool
		expected *CPE
	}{
		{
			name:    "CPE 2.2 with extended tilde format - language field",
			cpeStr:  "cpe:/a:mysql:mysql:5.7.12:::~~~enterprise~~",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "mysql",
				ProductName: "mysql",
				Version:     "5.7.12",
				Language:    "enterprise",
			},
		},
		{
			name:    "CPE 2.2 with only part",
			cpeStr:  "cpe:/a",
			wantErr: false,
			expected: &CPE{
				Part: *PartApplication,
			},
		},
		{
			name:    "CPE 2.2 with invalid part",
			cpeStr:  "cpe:/x:vendor:product:1.0",
			wantErr: true,
		},
		{
			name:    "CPE 2.2 with update and edition",
			cpeStr:  "cpe:/a:vendor:product:1.0:update:edition",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
				Update:      "update",
				Edition:     "edition",
			},
		},
		{
			name:    "CPE 2.2 with all basic fields",
			cpeStr:  "cpe:/a:vendor:product:1.0:update:edition:language",
			wantErr: false,
			expected: &CPE{
				Part:        *PartApplication,
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
				Update:      "update",
				Edition:     "edition",
				Language:    "language",
			},
		},
		{
			name:    "CPE 2.2 hardware",
			cpeStr:  "cpe:/h:intel:core_i7:1068g7",
			wantErr: false,
			expected: &CPE{
				Part:        *PartHardware,
				Vendor:      "intel",
				ProductName: "core_i7",
				Version:     "1068g7",
			},
		},
		{
			name:    "CPE 2.2 with extended format sw_edition from tilde",
			cpeStr:  "cpe:/a:vendor:product:1.0:::~~~~enterprise~~",
			wantErr: false,
			expected: &CPE{
				Part:            *PartApplication,
				Vendor:          "vendor",
				ProductName:     "product",
				Version:         "1.0",
				SoftwareEdition: "enterprise",
			},
		},
		{
			name:    "CPE 2.2 with extended format target hw from tilde",
			cpeStr:  "cpe:/a:vendor:product:1.0:::~~~~~~x86",
			wantErr: false,
			expected: &CPE{
				Part:           *PartApplication,
				Vendor:         "vendor",
				ProductName:    "product",
				Version:        "1.0",
				TargetHardware: "x86",
			},
		},
		{
			name:    "CPE 2.2 with empty part string",
			cpeStr:  "cpe:/",
			wantErr: false,
			expected: &CPE{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCpe22(tt.cpeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCpe22() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil && tt.expected != nil {
				if got.Part.ShortName != tt.expected.Part.ShortName {
					t.Errorf("ParseCpe22() Part = %v, want %v", got.Part.ShortName, tt.expected.Part.ShortName)
				}
				if got.Vendor != tt.expected.Vendor {
					t.Errorf("ParseCpe22() Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
				}
				if got.ProductName != tt.expected.ProductName {
					t.Errorf("ParseCpe22() ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
				}
				if got.Version != tt.expected.Version {
					t.Errorf("ParseCpe22() Version = %v, want %v", got.Version, tt.expected.Version)
				}
				if tt.expected.Update != "" && got.Update != tt.expected.Update {
					t.Errorf("ParseCpe22() Update = %v, want %v", got.Update, tt.expected.Update)
				}
				if tt.expected.Edition != "" && got.Edition != tt.expected.Edition {
					t.Errorf("ParseCpe22() Edition = %v, want %v", got.Edition, tt.expected.Edition)
				}
				if tt.expected.Language != "" && got.Language != tt.expected.Language {
					t.Errorf("ParseCpe22() Language = %v, want %v", got.Language, tt.expected.Language)
				}
				if tt.expected.SoftwareEdition != "" && got.SoftwareEdition != tt.expected.SoftwareEdition {
					t.Errorf("ParseCpe22() SoftwareEdition = %v, want %v", got.SoftwareEdition, tt.expected.SoftwareEdition)
				}
				if tt.expected.TargetHardware != "" && got.TargetHardware != tt.expected.TargetHardware {
					t.Errorf("ParseCpe22() TargetHardware = %v, want %v", got.TargetHardware, tt.expected.TargetHardware)
				}
			}
		})
	}
}

// TestFormatCpe22Extended tests additional edge cases for FormatCpe22
func TestFormatCpe22Extended(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected string
	}{
		{
			name: "nil CPE returns empty string",
			cpe:  nil,
			expected: "",
		},
		{
			name: "CPE with software edition",
			cpe: &CPE{
				Part:            *PartApplication,
				Vendor:          "mysql",
				ProductName:     "mysql",
				Version:         "5.7.12",
				SoftwareEdition: "enterprise",
			},
			expected: "cpe:/a:mysql:mysql:5%2e7%2e12::::~enterprise~~~",
		},
		{
			name: "CPE with target software",
			cpe: &CPE{
				Part:           *PartApplication,
				Vendor:         "vendor",
				ProductName:    "product",
				Version:        "1.0",
				TargetSoftware: "linux",
			},
			expected: "cpe:/a:vendor:product:1%2e0::::~~linux~~",
		},
		{
			name: "CPE with target hardware",
			cpe: &CPE{
				Part:           *PartApplication,
				Vendor:         "vendor",
				ProductName:    "product",
				Version:        "1.0",
				TargetHardware: "x86",
			},
			expected: "cpe:/a:vendor:product:1%2e0::::~~~x86~",
		},
		{
			name: "CPE with other field",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
				Other:       "custom",
			},
			expected: "cpe:/a:vendor:product:1%2e0::::~~~~custom",
		},
		{
			name: "CPE with edition and language but no extended",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
				Edition:     "pro",
				Language:    "en",
			},
			expected: "cpe:/a:vendor:product:1%2e0::pro:en",
		},
		{
			name: "CPE with update but no edition or language",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
				Update:      "sp1",
			},
			expected: "cpe:/a:vendor:product:1%2e0:sp1",
		},
		{
			name: "CPE with empty part defaults to wildcard",
			cpe: &CPE{
				Vendor:      "vendor",
				ProductName: "product",
				Version:     "1.0",
			},
			expected: "cpe:/*:vendor:product:1%2e0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCpe22(tt.cpe); got != tt.expected {
				t.Errorf("FormatCpe22() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUnescapeCpe22ValueExtended tests additional edge cases for unescapeCpe22Value
func TestUnescapeCpe22ValueExtended(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "percent-encode with unknown code - preserved",
			value:    "test%zz",
			expected: "test%zz",
		},
		{
			name:     "percent-encode with incomplete code",
			value:    "test%2",
			expected: "test%2",
		},
		{
			name:     "backslash percent-encode",
			value:    "test%5c",
			expected: "test\\",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeCpe22Value(tt.value); got != tt.expected {
				t.Errorf("unescapeCpe22Value() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestParseCpe22_ExtendedEdition tests parsing CPE 2.2 with extended format edition field
func TestParseCpe22_ExtendedEdition(t *testing.T) {
	// CPE 2.2 with ~ extended format where i==5 and extParts[0] is edition
	result, err := ParseCpe22("cpe:/a:vendor:product:1.0:update:edition~~~language~sw_ed~target_sw~target_hw~other")
	if err != nil {
		t.Fatalf("ParseCpe22() error = %v", err)
	}
	if string(result.Edition) != "edition" {
		t.Errorf("ParseCpe22() Edition = %q, want %q", result.Edition, "edition")
	}
	if result.TargetSoftware != "target_sw" {
		t.Errorf("ParseCpe22() TargetSoftware = %q, want %q", result.TargetSoftware, "target_sw")
	}
	if result.Other != "other" {
		t.Errorf("ParseCpe22() Other = %q, want %q", result.Other, "other")
	}
}

// TestFormatCpe22_EmptyFields tests FormatCpe22 with empty vendor, product, and version
func TestFormatCpe22_EmptyFields(t *testing.T) {
	cpe := &CPE{
		Part: *PartApplication,
	}
	result := FormatCpe22(cpe)
	if result != "cpe:/a:*:*:*" {
		t.Errorf("FormatCpe22() with empty fields = %q, want %q", result, "cpe:/a:*:*:*")
	}
}

	// TestParseCpe22_CoverageGap_TargetSoftwareFromTilde tests parsing target_sw from extended tilde format
	func TestParseCpe22_CoverageGap_TargetSoftwareFromTilde(t *testing.T) {
		cpe, err := ParseCpe22("cpe:/a:vendor:product:1.0:::~~~~~linux~~")
		if err != nil {
			t.Fatalf("ParseCpe22() error = %v", err)
		}
		if cpe.TargetSoftware != "linux" {
			t.Errorf("TargetSoftware = %q, want %q", cpe.TargetSoftware, "linux")
		}
	}

	// TestParseCpe22_CoverageGap_OtherFromTilde tests parsing other from extended tilde format
	func TestParseCpe22_CoverageGap_OtherFromTilde(t *testing.T) {
		cpe, err := ParseCpe22("cpe:/a:vendor:product:1.0:::~~~~~~~custom")
		if err != nil {
			t.Fatalf("ParseCpe22() error = %v", err)
		}
		if cpe.Other != "custom" {
			t.Errorf("Other = %q, want %q", cpe.Other, "custom")
		}
	}

	// TestFormatCpe22_CoverageGap_EditionOnlyNoExtended tests FormatCpe22 with edition only and no extended fields
	func TestFormatCpe22_CoverageGap_EditionOnlyNoExtended(t *testing.T) {
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      "vendor",
			ProductName: "product",
			Version:     "1.0",
			Update:      "*",
			Edition:     "pro",
		}
		result := FormatCpe22(cpe)
		if !containsStr(result, "pro") {
			t.Errorf("FormatCpe22() = %q, should contain edition 'pro'", result)
		}
	}

	// TestFormatCpe22_CoverageGap_LanguageOnlyNoExtended tests FormatCpe22 with language but no extended fields
	func TestFormatCpe22_CoverageGap_LanguageOnlyNoExtended(t *testing.T) {
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      "vendor",
			ProductName: "product",
			Version:     "1.0",
			Language:    "en",
		}
		result := FormatCpe22(cpe)
		if !containsStr(result, "en") {
			t.Errorf("FormatCpe22() = %q, should contain language 'en'", result)
		}
	}

	func containsStr(s, substr string) bool {
		for i := 0; i <= len(s)-len(substr); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	}
