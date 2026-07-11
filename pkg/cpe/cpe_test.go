package cpeskills

import (
	"testing"

	"github.com/scagogogo/versions"
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
			expected: "cpe:2.3:a:example\\.com:product%3aname:1\\.0:*:*:*:*:*:*:*",
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
	// 测试使用versions库的版本比较功能
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
			// 使用versions库的Version.CompareTo方法
			v1 := versions.NewVersion(tc.v1)
			v2 := versions.NewVersion(tc.v2)
			result := v1.CompareTo(v2)
			if result != tc.expected {
				t.Errorf("版本比较(%q, %q) = %d, 期望 %d", tc.v1, tc.v2, result, tc.expected)
			}
		})
	}
}

// TestCPECompareTo 测试CPE的CompareTo方法
func TestCPECompareTo(t *testing.T) {
	tests := []struct {
		name     string
		a        *CPE
		b        *CPE
		expected Relation
	}{
		{
			name: "equal CPEs",
			a: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			b: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: RelationEqual,
		},
		{
			name: "superset - ANY version",
			a: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     ValueANY,
			},
			b: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: RelationSuperset,
		},
		{
			name: "subset - specific version",
			a: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			b: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     ValueANY,
			},
			expected: RelationSubset,
		},
		{
			name: "disjoint - different vendors",
			a: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			b: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "reader",
				Version:     "10",
			},
			expected: RelationDisjoint,
		},
		{
			name:     "nil source",
			a:        nil,
			b:        &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows"},
			expected: RelationDisjoint,
		},
		{
			name:     "nil target",
			a:        &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows"},
			b:        nil,
			expected: RelationDisjoint,
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: RelationDisjoint,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.CompareTo(tt.b); got != tt.expected {
				t.Errorf("CompareTo() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestCPEIsSupersetOf 测试CPE的IsSupersetOf方法
func TestCPEIsSupersetOf(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     ValueANY,
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !a.IsSupersetOf(b) {
		t.Error("Expected ANY version to be superset of specific version")
	}
	if b.IsSupersetOf(a) {
		t.Error("Expected specific version not to be superset of ANY version")
	}

	// Equal CPEs are also superset of each other
	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if !c.IsSupersetOf(b) {
		t.Error("Expected equal CPEs to be superset of each other")
	}

	// Nil cases
	if a.IsSupersetOf(nil) {
		t.Error("Expected not superset with nil")
	}
}

// TestCPEIsSubsetOf 测试CPE的IsSubsetOf方法
func TestCPEIsSubsetOf(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     ValueANY,
	}

	if !a.IsSubsetOf(b) {
		t.Error("Expected specific version to be subset of ANY version")
	}
	if b.IsSubsetOf(a) {
		t.Error("Expected ANY version not to be subset of specific version")
	}

	// Equal CPEs are also subset of each other
	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if !c.IsSubsetOf(a) {
		t.Error("Expected equal CPEs to be subset of each other")
	}

	// Nil cases
	if a.IsSubsetOf(nil) {
		t.Error("Expected not subset with nil")
	}
}

// TestCPEIsDisjointWith 测试CPE的IsDisjointWith方法
func TestCPEIsDisjointWith(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "10",
	}

	if !a.IsDisjointWith(b) {
		t.Error("Expected disjoint CPEs")
	}

	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if a.IsDisjointWith(c) {
		t.Error("Expected equal CPEs not to be disjoint")
	}

	// Nil is disjoint with anything
	if !a.IsDisjointWith(nil) {
		t.Error("Expected nil to be disjoint")
	}
}

// TestCPEIsEqualTo 测试CPE的IsEqualTo方法
func TestCPEIsEqualTo(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !a.IsEqualTo(b) {
		t.Error("Expected equal CPEs")
	}

	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}
	if a.IsEqualTo(c) {
		t.Error("Expected different version CPEs not to be equal")
	}

	// Nil cases
	if a.IsEqualTo(nil) {
		t.Error("Expected not equal with nil")
	}
	if (&CPE{}).IsEqualTo(nil) {
		t.Error("Expected not equal with nil")
	}
}

// TestMatchCPEExtended 测试MatchCPE的更多边界情况
func TestMatchCPEExtended(t *testing.T) {
	// nil criteria
	if MatchCPE(nil, &CPE{}, DefaultMatchOptions()) {
		t.Error("Expected false for nil criteria")
	}
	// nil target
	if MatchCPE(&CPE{}, nil, DefaultMatchOptions()) {
		t.Error("Expected false for nil target")
	}
	// nil options should still work
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if !MatchCPE(criteria, target, nil) {
		t.Error("Expected match with nil options")
	}
	// criteria with wildcard product
	wildcardCriteria := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "*",
		Version:     "10",
	}
	if !MatchCPE(wildcardCriteria, target, DefaultMatchOptions()) {
		t.Error("Expected wildcard product to match")
	}
}

// TestMatchAttributeExtended 测试matchAttribute的更多边界情况
func TestParseCpe23Extended(t *testing.T) {
	tests := []struct {
		name     string
		cpeStr   string
		wantErr  bool
		expected *CPE
	}{
		{
			name:    "wildcard part",
			cpeStr:  "cpe:2.3:*:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &CPE{
				Cpe23:       "cpe:2.3:*:microsoft:windows:10:*:*:*:*:*:*:*",
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
		},
		{
			name:    "invalid part",
			cpeStr:  "cpe:2.3:x:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "wrong header",
			cpeStr:  "cpp:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "wrong version",
			cpeStr:  "cpe:2.2:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
		{
			name:    "too few parts",
			cpeStr:  "cpe:2.3:a:microsoft:windows",
			wantErr: true,
		},
		{
			name:    "with special characters in vendor",
			cpeStr:  "cpe:2.3:a:example\\.com:product:1.0:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &CPE{
				Vendor:      "example.com",
				ProductName: "product",
				Version:     "1.0",
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

			if err == nil && tt.expected != nil {
				if tt.expected.Vendor != "" && got.Vendor != tt.expected.Vendor {
					t.Errorf("ParseCpe23() Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
				}
				if tt.expected.ProductName != "" && got.ProductName != tt.expected.ProductName {
					t.Errorf("ParseCpe23() ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
				}
				if tt.expected.Version != "" && got.Version != tt.expected.Version {
					t.Errorf("ParseCpe23() Version = %v, want %v", got.Version, tt.expected.Version)
				}
			}
		})
	}
}

func TestFormatCpe23Extended(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected string
	}{
		{
			name: "empty Cpe23 generates from fields",
			cpe: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "10",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			expected: "cpe:2.3:a:microsoft:windows:10:sp1:pro:en:enterprise:linux:x86:custom",
		},
		{
			name: "existing Cpe23 takes precedence",
			cpe: &CPE{
				Cpe23:           "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "11",
			},
			expected: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
		},
		{
			name: "empty part defaults to wildcard",
			cpe: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			expected: "cpe:2.3:*:microsoft:windows:10:*:*:*:*:*:*:*",
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

func TestMatchAttributeExtended(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{"both ANY", "*", "*", true},
		{"a ANY", "*", "value", true},
		{"b ANY", "value", "*", true},
		{"both NA", "-", "-", true},
		{"a NA", "-", "value", false},
		{"b NA", "value", "-", false},
		{"exact match", "value", "value", true},
		{"no match", "value1", "value2", false},
		{"empty strings", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchAttribute(tt.a, tt.b); got != tt.expected {
				t.Errorf("matchAttribute(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestCPEMatchExtended 测试CPE Match的更多属性覆盖
func TestCPEMatchExtended(t *testing.T) {
	// Test matching with Update, Edition, Language
	cpe1 := &CPE{
		Cpe23:           "cpe:2.3:a:microsoft:windows:10:sp1:pro:en:*:*:*:*",
		Part:            *PartApplication,
		Vendor:          "microsoft",
		ProductName:     "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "*",
		TargetSoftware:  "*",
		TargetHardware:  "*",
		Other:           "*",
	}
	cpe2 := &CPE{
		Cpe23:           "cpe:2.3:a:microsoft:windows:10:sp1:pro:en:*:*:*:*",
		Part:            *PartApplication,
		Vendor:          "microsoft",
		ProductName:     "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "*",
		TargetSoftware:  "*",
		TargetHardware:  "*",
		Other:           "*",
	}
	if !cpe1.Match(cpe2) {
		t.Error("Expected identical CPEs to match")
	}

	// Test mismatch on Update
	cpe3 := &CPE{
		Part:    *PartApplication,
		Vendor:  "microsoft",
		ProductName: "windows",
		Version:     "10",
		Update:      "sp2",
	}
	if cpe1.Match(cpe3) {
		t.Error("Expected mismatch on Update")
	}

	// Test mismatch on Edition
	cpe4 := &CPE{
		Part:    *PartApplication,
		Vendor:  "microsoft",
		ProductName: "windows",
		Version:     "10",
		Update:      "sp1",
		Edition:     "home",
	}
	if cpe1.Match(cpe4) {
		t.Error("Expected mismatch on Edition")
	}

	// Test mismatch on Language
	cpe5 := &CPE{
		Part:    *PartApplication,
		Vendor:  "microsoft",
		ProductName: "windows",
		Version:     "10",
		Update:      "sp1",
		Edition:     "pro",
		Language:    "de",
	}
	if cpe1.Match(cpe5) {
		t.Error("Expected mismatch on Language")
	}

	// Test mismatch on SoftwareEdition (both specific, different values)
	cpe6a := &CPE{
		Cpe23:           "cpe:2.3:a:microsoft:windows:10:*:*:*:enterprise:*:*:*",
		Part:            *PartApplication,
		Vendor:          "microsoft",
		ProductName:     "windows",
		Version:         "10",
		SoftwareEdition: "enterprise",
	}
	cpe6b := &CPE{
		Cpe23:           "cpe:2.3:a:microsoft:windows:10:*:*:*:standard:*:*:*",
		Part:            *PartApplication,
		Vendor:          "microsoft",
		ProductName:     "windows",
		Version:         "10",
		SoftwareEdition: "standard",
	}
	if cpe6a.Match(cpe6b) {
		t.Error("Expected mismatch on SoftwareEdition")
	}

	// Test mismatch on TargetSoftware (both specific, different values)
	cpe7a := &CPE{
		Cpe23:          "cpe:2.3:a:microsoft:windows:10:*:*:*:*:linux:*:*",
		Part:           *PartApplication,
		Vendor:         "microsoft",
		ProductName:    "windows",
		Version:        "10",
		TargetSoftware: "linux",
	}
	cpe7b := &CPE{
		Cpe23:          "cpe:2.3:a:microsoft:windows:10:*:*:*:*:windows:*:*",
		Part:           *PartApplication,
		Vendor:         "microsoft",
		ProductName:    "windows",
		Version:        "10",
		TargetSoftware: "windows",
	}
	if cpe7a.Match(cpe7b) {
		t.Error("Expected mismatch on TargetSoftware")
	}

	// Test mismatch on TargetHardware (both specific, different values)
	cpe8a := &CPE{
		Cpe23:          "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:x86:*",
		Part:           *PartApplication,
		Vendor:         "microsoft",
		ProductName:    "windows",
		Version:        "10",
		TargetHardware: "x86",
	}
	cpe8b := &CPE{
		Cpe23:          "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:arm:*",
		Part:           *PartApplication,
		Vendor:         "microsoft",
		ProductName:    "windows",
		Version:        "10",
		TargetHardware: "arm",
	}
	if cpe8a.Match(cpe8b) {
		t.Error("Expected mismatch on TargetHardware")
	}

	// Test mismatch on Other (both specific, different values)
	cpe9a := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:custom1",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
		Other:       "custom1",
	}
	cpe9b := &CPE{
		Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:custom2",
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
		Other:       "custom2",
	}
	if cpe9a.Match(cpe9b) {
		t.Error("Expected mismatch on Other")
	}
}

	// TestFormatCpe23_CoverageGap_AllFieldsPopulated tests FormatCpe23 with all fields having specific values
	func TestFormatCpe23_CoverageGap_AllFieldsPopulated(t *testing.T) {
		cpe := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "sp1",
			Edition:         "pro",
			Language:        "en",
			SoftwareEdition: "enterprise",
			TargetSoftware:  "linux",
			TargetHardware:  "x86",
			Other:           "custom",
		}
		result := FormatCpe23(cpe)
		expected := "cpe:2.3:a:microsoft:windows:10:sp1:pro:en:enterprise:linux:x86:custom"
		if result != expected {
			t.Errorf("FormatCpe23() = %q, want %q", result, expected)
		}
	}
