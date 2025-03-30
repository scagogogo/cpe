package cpe

import (
	"testing"
)

// TestCPEMatch 测试CPE匹配功能
func TestCPEMatch(t *testing.T) {
	tests := []struct {
		name     string
		cpe1     *CPE
		cpe2     *CPE
		expected bool
	}{
		{
			name: "完全相同的CPE应匹配",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: true,
		},
		{
			name: "通配符匹配",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "*",
			},
			expected: true,
		},
		{
			name: "不匹配的版本",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
			expected: false,
		},
		{
			name: "不匹配的产品",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:office:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
				Version:     "10",
			},
			expected: false,
		},
		{
			name: "不匹配的Part",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartOperationSystem,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: false,
		},
		{
			name: "NA 值匹配",
			cpe1: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:-:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "-",
			},
			cpe2: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:-:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "-",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cpe1.Match(tt.cpe2); got != tt.expected {
				t.Errorf("CPE.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestGetURI 测试GetURI方法
func TestGetURI(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected string
	}{
		{
			name: "通过字段生成URI",
			cpe: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "10",
				Update:          "*",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name: "直接使用已有的Cpe23",
			cpe: &CPE{
				Cpe23: "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
			},
			expected: "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		},
		{
			name:     "nil CPE",
			cpe:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cpe.GetURI(); got != tt.expected {
				t.Errorf("CPE.GetURI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestParseCpe23 测试解析CPE 2.3格式字符串
func TestParseCpe23(t *testing.T) {
	tests := []struct {
		name     string
		cpeStr   string
		wantErr  bool
		expected *CPE
	}{
		{
			name:    "有效的CPE 2.3字符串",
			cpeStr:  "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "*",
				Edition:     "*",
				Language:    "*",
			},
		},
		{
			name:    "无效的CPE 2.3格式",
			cpeStr:  "cpe:2.3:a:microsoft:windows:10",
			wantErr: true,
		},
		{
			name:    "无效的Part值",
			cpeStr:  "cpe:2.3:x:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "非CPE字符串",
			cpeStr:  "not-a-cpe-string",
			wantErr: true,
		},
		{
			name:    "操作系统CPE",
			cpeStr:  "cpe:2.3:o:microsoft:windows:11:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &CPE{
				Cpe23:       "cpe:2.3:o:microsoft:windows:11:*:*:*:*:*:*:*",
				Part:        *PartOperationSystem,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
		},
		{
			name:    "硬件CPE",
			cpeStr:  "cpe:2.3:h:intel:core_i7:1068g7:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &CPE{
				Cpe23:       "cpe:2.3:h:intel:core_i7:1068g7:*:*:*:*:*:*:*",
				Part:        *PartHardware,
				Vendor:      "intel",
				ProductName: "core_i7",
				Version:     "1068g7",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCpe23(tt.cpeStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCpe23() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if got.Cpe23 != tt.expected.Cpe23 {
					t.Errorf("ParseCpe23() Cpe23 = %v, want %v", got.Cpe23, tt.expected.Cpe23)
				}
				if got.Part.ShortName != tt.expected.Part.ShortName {
					t.Errorf("ParseCpe23() Part = %v, want %v", got.Part.ShortName, tt.expected.Part.ShortName)
				}
				if got.Vendor != tt.expected.Vendor {
					t.Errorf("ParseCpe23() Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
				}
				if got.ProductName != tt.expected.ProductName {
					t.Errorf("ParseCpe23() ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
				}
				if got.Version != tt.expected.Version {
					t.Errorf("ParseCpe23() Version = %v, want %v", got.Version, tt.expected.Version)
				}
			}
		})
	}
}

// TestFormatCpe23 测试格式化CPE为2.3格式字符串
func TestFormatCpe23(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected string
	}{
		{
			name: "标准格式化",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "*",
				Edition:     "*",
				Language:    "*",
			},
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name: "已有Cpe23值",
			cpe: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
				Version:     "2019",
			},
			expected: "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
		},
		{
			name: "特殊字符转义",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "example.com",
				ProductName: "product:name",
				Version:     "1.0",
			},
			expected: "cpe:2.3:a:example\\.com:product\\:name:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatCpe23(tt.cpe); got != tt.expected {
				t.Errorf("FormatCpe23() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchCPE 测试MatchCPE函数
func TestMatchCPE(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *MatchOptions
		expected bool
	}{
		{
			name: "基本匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options:  DefaultMatchOptions(),
			expected: true,
		},
		{
			name: "忽略版本匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
			options: &MatchOptions{
				IgnoreVersion: true,
			},
			expected: true,
		},
		{
			name: "不匹配 - 不同产品",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
				Version:     "10",
			},
			options:  DefaultMatchOptions(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchCPE(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("MatchCPE() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDefaultMatchOptions 测试DefaultMatchOptions函数
func TestDefaultMatchOptions(t *testing.T) {
	options := DefaultMatchOptions()

	if options.IgnoreVersion {
		t.Errorf("DefaultMatchOptions().IgnoreVersion = %v, want %v", options.IgnoreVersion, false)
	}

	if !options.AllowSubVersions {
		t.Errorf("DefaultMatchOptions().AllowSubVersions = %v, want %v", options.AllowSubVersions, true)
	}

	if options.UseRegex {
		t.Errorf("DefaultMatchOptions().UseRegex = %v, want %v", options.UseRegex, false)
	}

	if options.VersionRange {
		t.Errorf("DefaultMatchOptions().VersionRange = %v, want %v", options.VersionRange, false)
	}
}

// TestCompareVersionsString 测试版本比较功能
func TestCompareVersionsString(t *testing.T) {
	// 测试 compareVersionStrings 函数功能
	testCases := []struct {
		name     string
		v1       string
		v2       string
		expected int
	}{
		{"相等版本", "1.0.0", "1.0.0", 0},
		{"v1小于v2 - 主版本号", "1.0.0", "2.0.0", -1},
		{"v1大于v2 - 主版本号", "2.0.0", "1.0.0", 1},
		{"v1小于v2 - 次版本号", "1.0.0", "1.1.0", -1},
		{"v1大于v2 - 次版本号", "1.1.0", "1.0.0", 1},
		{"v1小于v2 - 修订号", "1.0.0", "1.0.1", -1},
		{"v1大于v2 - 修订号", "1.0.1", "1.0.0", 1},
		{"v1小于v2 - 长度不同", "1.0", "1.0.1", -1},
		{"v1大于v2 - 长度不同", "1.0.1", "1.0", 1},
		{"字母版本比较", "1.0a", "1.0b", -1},
		{"数字与字母混合", "1.0.0", "1.0.0a", -1},
		{"复杂版本格式", "1.0-alpha", "1.0-beta", -1},
		{"带下划线版本", "1.0_alpha", "1.0_beta", -1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := compareVersionStrings(tc.v1, tc.v2)
			if result != tc.expected {
				t.Errorf("compareVersionStrings(%q, %q) = %d, 期望 %d", tc.v1, tc.v2, result, tc.expected)
			}
		})
	}
}
