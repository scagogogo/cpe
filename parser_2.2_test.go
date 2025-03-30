package cpe

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
			expected: "cpe:/a:example%2ecom:product%3aname:1.0",
		},
		{
			name: "硬件格式化",
			cpe: &CPE{
				Part:        *PartHardware,
				Vendor:      "intel",
				ProductName: "core_i7",
				Version:     "1068g7",
			},
			expected: "cpe:/h:intel:core_i7:1068g7",
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
			expected: "cpe:2.3:a:example\\.com:product\\:name:1.0:*:*:*:*:*:*:*",
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

// TestUnescapeCpe22Value 测试CPE 2.2值反转义
func TestUnescapeCpe22Value(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "无转义字符的值",
			value:    "windows",
			expected: "windows",
		},
		{
			name:     "转义的点",
			value:    "example%3a",
			expected: "example:",
		},
		{
			name:     "转义的斜杠",
			value:    "a%2fb",
			expected: "a/b",
		},
		{
			name:     "转义的波浪号",
			value:    "version%7erc1",
			expected: "version~rc1",
		},
		{
			name:     "特殊值不需要处理",
			value:    "*",
			expected: "*",
		},
		{
			name:     "特殊值不需要处理",
			value:    "-",
			expected: "-",
		},
		{
			name:     "空值不需要处理",
			value:    "",
			expected: "",
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
