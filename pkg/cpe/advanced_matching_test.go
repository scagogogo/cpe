package cpeskills

import (
	"testing"
)

// TestNewAdvancedMatchOptions 测试创建高级匹配选项
func TestNewAdvancedMatchOptions(t *testing.T) {
	options := NewAdvancedMatchOptions()

	// 检查默认值
	if options.UseRegex {
		t.Errorf("NewAdvancedMatchOptions().UseRegex = %v, want false", options.UseRegex)
	}

	if options.IgnoreCase {
		t.Errorf("NewAdvancedMatchOptions().IgnoreCase = %v, want false", options.IgnoreCase)
	}

	if options.UseFuzzyMatch {
		t.Errorf("NewAdvancedMatchOptions().UseFuzzyMatch = %v, want false", options.UseFuzzyMatch)
	}

	if options.MatchCommonOnly {
		t.Errorf("NewAdvancedMatchOptions().MatchCommonOnly = %v, want false", options.MatchCommonOnly)
	}

	if options.PartialMatch {
		t.Errorf("NewAdvancedMatchOptions().PartialMatch = %v, want false", options.PartialMatch)
	}

	if options.MatchMode != "exact" {
		t.Errorf("NewAdvancedMatchOptions().MatchMode = %v, want 'exact'", options.MatchMode)
	}

	if options.VersionCompareMode != "exact" {
		t.Errorf("NewAdvancedMatchOptions().VersionCompareMode = %v, want 'exact'", options.VersionCompareMode)
	}

	if options.FieldOptions == nil {
		t.Errorf("NewAdvancedMatchOptions().FieldOptions is nil, want a map")
	}
}

// TestAdvancedMatchCPE 测试高级CPE匹配
func TestAdvancedMatchCPE(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "精确匹配模式",
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
			options: &AdvancedMatchOptions{
				MatchMode: "exact",
			},
			expected: true,
		},
		{
			name: "忽略大小写匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "Microsoft",
				ProductName: "Windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				IgnoreCase: true,
			},
			expected: true,
		},
		{
			name: "正则表达式匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "1.*",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "部分匹配模式",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				PartialMatch: true,
			},
			expected: true,
		},
		{
			name: "子集匹配模式",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				MatchMode: "subset",
			},
			expected: true,
		},
		{
			name: "超集匹配模式",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "pro",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				MatchMode: "superset",
			},
			expected: true,
		},
		{
			name: "仅匹配常见字段",
			criteria: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "10",
				SoftwareEdition: "professional",
			},
			target: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "10",
				SoftwareEdition: "home",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: true,
			},
			expected: true,
		},
		{
			name: "版本范围匹配",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionLower:       "9",
				VersionUpper:       "12",
			},
			expected: true,
		},
		{
			name: "不匹配 - 不同的产品",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "不匹配 - 不同的供应商",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "reader",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "reader",
			},
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdvancedMatchCPE(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("AdvancedMatchCPE() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchWithRegex 测试正则表达式匹配
func TestMatchWithRegex(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "简单正则匹配",
			criteria: &CPE{
				Vendor:      "micro.*",
				ProductName: "windows",
			},
			target: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "精确版本正则",
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10\\.[0-9]+",
			},
			target: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10.2",
			},
			options: &AdvancedMatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "版本不匹配正则",
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11\\.[0-9]+",
			},
			target: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10.2",
			},
			options: &AdvancedMatchOptions{
				UseRegex: true,
			},
			expected: false,
		},
		{
			name: "忽略大小写匹配",
			criteria: &CPE{
				Vendor:      "Microsoft",
				ProductName: "Windows",
			},
			target: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				UseRegex:   true,
				IgnoreCase: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchWithRegex(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchWithRegex() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchNonVersionFields 测试非版本字段匹配
func TestMatchNonVersionFields(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "基本字段匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  &AdvancedMatchOptions{},
			expected: true,
		},
		{
			name: "忽略大小写",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "Microsoft",
				ProductName: "Windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				IgnoreCase: true,
			},
			expected: true,
		},
		{
			name: "字段不匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "需要字段权重 - 部分匹配",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Edition:     "professional",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Edition:     "home",
			},
			options: &AdvancedMatchOptions{
				FieldOptions: map[string]FieldMatchOption{
					"part":    {Weight: 0.3, Required: true},
					"vendor":  {Weight: 0.3, Required: true},
					"product": {Weight: 0.3, Required: true},
					"edition": {Weight: 0.1, Required: false},
				},
				ScoreThreshold: 0.9, // 90%匹配度
			},
			expected: true, // 因为主要字段都匹配，总分超过阈值
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchNonVersionFields(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchNonVersionFields() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestAdvancedMatchCPEExtended tests additional branches of AdvancedMatchCPE
func TestAdvancedMatchCPEExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name:     "nil criteria returns false",
			criteria: nil,
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options:  NewAdvancedMatchOptions(),
			expected: false,
		},
		{
			name: "nil target returns false",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			target:   nil,
			options:  NewAdvancedMatchOptions(),
			expected: false,
		},
		{
			name: "nil options uses defaults",
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
			options:  nil,
			expected: true,
		},
		{
			name: "distance mode match",
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
			options: &AdvancedMatchOptions{
				MatchMode:      "distance",
				ScoreThreshold: 0.7,
				FieldOptions:   make(map[string]FieldMatchOption),
			},
			expected: true,
		},
		{
			name: "distance mode no match - threshold too high",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "reader",
			},
			options: &AdvancedMatchOptions{
				MatchMode:      "distance",
				ScoreThreshold: 0.99,
				FieldOptions:   make(map[string]FieldMatchOption),
			},
			expected: false,
		},
		{
			name: "unknown match mode falls through to default",
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
			options: &AdvancedMatchOptions{
				MatchMode: "unknown_mode",
			},
			expected: true,
		},
		{
			name: "fuzzy match - containment",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "micro",
				ProductName: "win",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				UseFuzzyMatch:      true,
				VersionCompareMode: "exact",
			},
			expected: true,
		},
		{
			name: "subset mode - match with non-common fields",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
			},
			options: &AdvancedMatchOptions{
				MatchMode:     "subset",
				MatchCommonOnly: false,
			},
			expected: true,
		},
		{
			name: "superset mode - criteria version empty returns false",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				MatchMode:      "superset",
				MatchCommonOnly: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AdvancedMatchCPE(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("AdvancedMatchCPE() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchCommonFieldsExtended tests additional branches of matchCommonFields
func TestMatchCommonFieldsExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "version compare mode greater",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: true,
		},
		{
			name: "version compare mode greater fails",
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
				Version:     "9",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: false,
		},
		{
			name: "version compare mode greaterOrEqual",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greaterOrEqual",
			},
			expected: true,
		},
		{
			name: "version compare mode less",
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
				Version:     "9",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "less",
			},
			expected: true,
		},
		{
			name: "version compare mode lessOrEqual",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "lessOrEqual",
			},
			expected: true,
		},
		{
			name: "version compare mode range - in range",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionLower:       "9",
				VersionUpper:       "12",
			},
			expected: true,
		},
		{
			name: "version compare mode range - out of range high",
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
				Version:     "13",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionLower:       "9",
				VersionUpper:       "12",
			},
			expected: false,
		},
		{
			name: "version compare mode range - out of range low",
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
				Version:     "8",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionLower:       "9",
				VersionUpper:       "12",
			},
			expected: false,
		},
		{
			name: "version compare mode range - only lower bound",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionLower:       "9",
			},
			expected: true,
		},
		{
			name: "version compare mode range - only upper bound",
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
				Version:     "8",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "range",
				VersionUpper:       "9",
			},
			expected: true,
		},
		{
			name: "version compare default unknown mode - exact match",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "unknown",
			},
			expected: true,
		},
		{
			name: "version compare default unknown mode - no match",
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
			options: &AdvancedMatchOptions{
				VersionCompareMode: "unknown",
			},
			expected: false,
		},
		{
			name: "fuzzy match with contains check",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "soft",
				ProductName: "win",
				Version:     "1",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				UseFuzzyMatch:      true,
				VersionCompareMode: "exact",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCommonFields(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchCommonFields() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchWithRegexExtended tests additional branches of matchWithRegex
func TestMatchWithRegexExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "regex match with non-common fields",
			criteria: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Version:         "10",
				Update:          "sp.*",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "ent.*",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom.*",
			},
			target: &CPE{
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
				Other:           "custom1",
			},
			options: &AdvancedMatchOptions{
				UseRegex:      true,
				MatchCommonOnly: false,
			},
			expected: true,
		},
		{
			name: "regex match non-common field mismatch",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp3",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
			},
			options: &AdvancedMatchOptions{
				UseRegex:      true,
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "regex with invalid pattern falls back to exact match",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "[invalid",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "[invalid",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "regex with invalid pattern and ignore case falls back to EqualFold",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "[invalid",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "[INVALID",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				UseRegex:   true,
				IgnoreCase: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchWithRegex(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchWithRegex() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchFieldExtended tests additional branches of matchField
func TestMatchFieldExtended(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name:     "both NA values match",
			a:        "-",
			b:        "-",
			options:  &AdvancedMatchOptions{},
			expected: true,
		},
		{
			name:     "NA does not match regular value",
			a:        "-",
			b:        "value",
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name:     "ignore case match",
			a:        "Windows",
			b:        "windows",
			options:  &AdvancedMatchOptions{IgnoreCase: true},
			expected: true,
		},
		{
			name:     "fuzzy match with contains",
			a:        "soft",
			b:        "microsoft",
			options:  &AdvancedMatchOptions{UseFuzzyMatch: true},
			expected: true,
		},
		{
			name:     "fuzzy match reverse contains",
			a:        "microsoft",
			b:        "soft",
			options:  &AdvancedMatchOptions{UseFuzzyMatch: true},
			expected: true,
		},
		{
			name:     "fuzzy match no containment",
			a:        "adobe",
			b:        "microsoft",
			options:  &AdvancedMatchOptions{UseFuzzyMatch: true},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchField(tt.a, tt.b, tt.options); got != tt.expected {
				t.Errorf("matchField() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchFieldWithRegexExtended tests additional branches of matchFieldWithRegex
func TestMatchFieldWithRegexExtended(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name:     "empty a pattern matches",
			a:        "",
			b:        "anything",
			options:  &AdvancedMatchOptions{},
			expected: true,
		},
		{
			name:     "star a pattern matches",
			a:        "*",
			b:        "anything",
			options:  &AdvancedMatchOptions{},
			expected: true,
		},
		{
			name:     "empty b no match",
			a:        "pattern",
			b:        "",
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name:     "NA b no match",
			a:        "pattern",
			b:        "-",
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name:     "star b matches",
			a:        "pattern",
			b:        "*",
			options:  &AdvancedMatchOptions{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchFieldWithRegex(tt.a, tt.b, tt.options); got != tt.expected {
				t.Errorf("matchFieldWithRegex() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchPartialExtended tests additional branches of matchPartial
func TestMatchPartialExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "partial match with non-common fields",
			criteria: &CPE{
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
			target: &CPE{
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
			options: &AdvancedMatchOptions{
				PartialMatch:    true,
				MatchCommonOnly: false,
			},
			expected: true,
		},
		{
			name: "partial match with wildcard criteria fields skipped",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "*",
				ProductName: "windows",
				Version:     "*",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				PartialMatch: true,
			},
			expected: true,
		},
		{
			name: "partial match version compare mode",
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
			options: &AdvancedMatchOptions{
				PartialMatch:       true,
				VersionCompareMode: "greater",
			},
			expected: true,
		},
		{
			name: "partial match non-common field mismatch",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Edition:     "professional",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Edition:     "home",
			},
			options: &AdvancedMatchOptions{
				PartialMatch:    true,
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "partial match empty criteria fields skipped",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "",
				ProductName: "windows",
				Version:     "",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "anything",
				ProductName: "windows",
				Version:     "anything",
			},
			options: &AdvancedMatchOptions{
				PartialMatch: true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchPartial(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchPartial() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestCompareVersionsExtended tests additional branches of compareVersions
func TestCompareVersionsExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "wildcard criteria version",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "*",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: true,
		},
		{
			name: "wildcard target version",
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
				Version:     "*",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: true,
		},
		{
			name: "NA criteria version",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "-",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: false,
		},
		{
			name: "NA target version",
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
				Version:     "-",
			},
			options: &AdvancedMatchOptions{
				VersionCompareMode: "greater",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareVersions(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("compareVersions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchSubsetExtended tests additional branches of matchSubset
func TestMatchSubsetExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name:     "nil criteria",
			criteria: nil,
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "nil target",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target:   nil,
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "subset match with all non-common fields",
			criteria: &CPE{
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
			target: &CPE{
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
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: true,
		},
		{
			name: "subset mismatch on non-common field",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Update:      "sp1",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Update:      "sp2",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "subset with empty part field skipped",
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSubset(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchSubset() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchSupersetExtended tests additional branches of matchSuperset
func TestMatchSupersetExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "nil criteria",
			criteria: nil,
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "nil target",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target:   nil,
			options:  &AdvancedMatchOptions{},
			expected: false,
		},
		{
			name: "superset match with non-common fields",
			criteria: &CPE{
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
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: true,
		},
		{
			name: "superset mismatch on target vendor",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "windows",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "superset mismatch on target product",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "office",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "superset with target version and criteria version empty fails",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: false,
		},
		{
			name: "superset with target version and criteria wildcard version fails",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "*",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchSuperset(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchSuperset() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchDistanceExtended tests additional branches of matchDistance
func TestMatchDistanceExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "distance match with required field that fails",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "reader",
				Version:     "10",
			},
			options: &AdvancedMatchOptions{
				ScoreThreshold: 0.7,
				FieldOptions: map[string]FieldMatchOption{
					"vendor": {Weight: 1.0, Required: true},
				},
			},
			expected: false,
		},
		{
			name: "distance match with version compare non-exact",
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
			options: &AdvancedMatchOptions{
				ScoreThreshold:     0.7,
				VersionCompareMode: "greater",
				FieldOptions:       make(map[string]FieldMatchOption),
			},
			expected: true,
		},
		{
			name: "distance match with non-common fields",
			criteria: &CPE{
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
			target: &CPE{
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
			options: &AdvancedMatchOptions{
				ScoreThreshold:   0.7,
				MatchCommonOnly:  false,
				FieldOptions:     make(map[string]FieldMatchOption),
			},
			expected: true,
		},
		{
			name: "distance match with custom weights",
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
			options: &AdvancedMatchOptions{
				ScoreThreshold: 0.7,
				FieldOptions: map[string]FieldMatchOption{
					"part":    {Weight: 2.0},
					"vendor":  {Weight: 2.0},
					"product": {Weight: 2.0},
				},
			},
			expected: true,
		},
		{
			name: "distance match below threshold",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "adobe",
				ProductName: "reader",
			},
			options: &AdvancedMatchOptions{
				ScoreThreshold: 0.9,
				FieldOptions:   make(map[string]FieldMatchOption),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchDistance(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchDistance() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMatchNonVersionFieldsExtended tests additional branches of matchNonVersionFields
func TestMatchNonVersionFieldsExtended(t *testing.T) {
	tests := []struct {
		name     string
		criteria *CPE
		target   *CPE
		options  *AdvancedMatchOptions
		expected bool
	}{
		{
			name: "non-version fields match with score below threshold",
			criteria: &CPE{
				Part:        *PartApplication,
				Vendor:      "novendor",
				ProductName: "noproduct",
				Edition:     "different",
				Language:    "different",
			},
			target: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Edition:     "pro",
				Language:    "en",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
				ScoreThreshold:  0.99,
			},
			expected: false,
		},
		{
			name: "non-version fields match all non-common fields matching",
			criteria: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			target: &CPE{
				Part:            *PartApplication,
				Vendor:          "microsoft",
				ProductName:     "windows",
				Update:          "sp1",
				Edition:         "pro",
				Language:        "en",
				SoftwareEdition: "enterprise",
				TargetSoftware:  "linux",
				TargetHardware:  "x86",
				Other:           "custom",
			},
			options: &AdvancedMatchOptions{
				MatchCommonOnly: false,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchNonVersionFields(tt.criteria, tt.target, tt.options); got != tt.expected {
				t.Errorf("matchNonVersionFields() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestIsRequiredFieldExtended tests isRequiredField edge case
func TestIsRequiredFieldExtended(t *testing.T) {
	// Test with nil FieldOptions map - should return false
	options := &AdvancedMatchOptions{
		FieldOptions: nil,
	}
	if isRequiredField(options, "vendor") {
		t.Error("isRequiredField with nil FieldOptions should return false")
	}
}

// TestMatchCommonFieldsAllMatch tests matchCommonFields where all fields match and return true
func TestMatchCommonFieldsAllMatch(t *testing.T) {
	// Test VersionCompareMode != "exact" with compareVersions returning true
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
	options := &AdvancedMatchOptions{
		VersionCompareMode: "greaterOrEqual",
	}
	if !matchCommonFields(criteria, target, options) {
		t.Error("matchCommonFields with matching fields should return true")
	}

	// Test with VersionCompareMode = "exact" and matching versions
	options2 := &AdvancedMatchOptions{
		VersionCompareMode: "exact",
	}
	if !matchCommonFields(criteria, target, options2) {
		t.Error("matchCommonFields with exact version match should return true")
	}
}

// TestMatchWithRegexAllMatch tests matchWithRegex where all fields match including non-common
func TestMatchWithRegexAllMatch(t *testing.T) {
	criteria := &CPE{
		Part:            *PartApplication,
		Vendor:          "micro.*",
		ProductName:     "win.*",
		Version:         "10.*",
		Update:          "sp.*",
		Edition:         "pro.*",
		Language:        "en.*",
		SoftwareEdition: "ent.*",
		TargetSoftware:  "lin.*",
		TargetHardware:  "x86.*",
		Other:           "cus.*",
	}
	target := &CPE{
		Part:            *PartApplication,
		Vendor:          "microsoft",
		ProductName:     "windows",
		Version:         "10.0",
		Update:          "sp1",
		Edition:         "professional",
		Language:        "en-us",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86_64",
		Other:           "custom",
	}
	options := &AdvancedMatchOptions{
		UseRegex:       true,
		MatchCommonOnly: false,
	}
	if !matchWithRegex(criteria, target, options) {
		t.Error("matchWithRegex with all matching regex fields should return true")
	}
}

// TestMatchWithRegexNonCommonMismatch tests matchWithRegex failing on non-common fields
func TestMatchWithRegexNonCommonMismatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
		Update:      "sp2",
		Edition:     "pro",
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
		Update:      "sp1",
		Edition:     "home",
	}
	options := &AdvancedMatchOptions{
		UseRegex:       true,
		MatchCommonOnly: false,
	}
	if matchWithRegex(criteria, target, options) {
		t.Error("matchWithRegex with mismatched non-common fields should return false")
	}
}

// TestMatchPartialAllFields tests matchPartial with various field combinations
func TestMatchPartialAllFields(t *testing.T) {
	options := &AdvancedMatchOptions{MatchCommonOnly: false}

	// Test with all fields matching in partial mode
	criteria := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro", Language: "en",
		SoftwareEdition: "enterprise", TargetSoftware: "linux", TargetHardware: "x86", Other: "custom",
	}
	target := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro", Language: "en",
		SoftwareEdition: "enterprise", TargetSoftware: "linux", TargetHardware: "x86", Other: "custom",
	}
	if !matchPartial(criteria, target, options) {
		t.Error("matchPartial with all matching fields should return true")
	}

	// Test with wildcard criteria fields (should skip those)
	criteria2 := &CPE{Part: *PartApplication, Vendor: "*", ProductName: "windows", Version: "*"}
	target2 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchPartial(criteria2, target2, options) {
		t.Error("matchPartial with wildcard criteria should match")
	}

	// Test with empty criteria fields (should skip those)
	criteria3 := &CPE{ProductName: "windows"}
	target3 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchPartial(criteria3, target3, options) {
		t.Error("matchPartial with empty criteria fields should skip them")
	}

	// Test non-common field mismatch: Update
	criteria4 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", Update: "sp2"}
	target4 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", Update: "sp1"}
	if matchPartial(criteria4, target4, options) {
		t.Error("matchPartial with Update mismatch should return false")
	}

	// Test non-common field mismatch: Edition
	criteria5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", Edition: "professional"}
	target5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", Edition: "home"}
	if matchPartial(criteria5, target5, options) {
		t.Error("matchPartial with Edition mismatch should return false")
	}

	// Test non-common field mismatch: Language
	criteria6 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", Language: "fr"}
	target6 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", Language: "en"}
	if matchPartial(criteria6, target6, options) {
		t.Error("matchPartial with Language mismatch should return false")
	}

	// Test non-common field mismatch: SoftwareEdition
	criteria7 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", SoftwareEdition: "enterprise"}
	target7 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", SoftwareEdition: "home"}
	if matchPartial(criteria7, target7, options) {
		t.Error("matchPartial with SoftwareEdition mismatch should return false")
	}

	// Test non-common field mismatch: TargetSoftware
	criteria8 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", TargetSoftware: "linux"}
	target8 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", TargetSoftware: "windows"}
	if matchPartial(criteria8, target8, options) {
		t.Error("matchPartial with TargetSoftware mismatch should return false")
	}

	// Test non-common field mismatch: TargetHardware
	criteria9 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", TargetHardware: "arm"}
	target9 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", TargetHardware: "x86"}
	if matchPartial(criteria9, target9, options) {
		t.Error("matchPartial with TargetHardware mismatch should return false")
	}

	// Test non-common field mismatch: Other
	criteria10 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*", Other: "custom1"}
	target10 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10", Other: "custom2"}
	if matchPartial(criteria10, target10, options) {
		t.Error("matchPartial with Other mismatch should return false")
	}

	// Test with version compare mode
	criteria11 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "9"}
	target11 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options11 := &AdvancedMatchOptions{VersionCompareMode: "greater"}
	if !matchPartial(criteria11, target11, options11) {
		t.Error("matchPartial with version compare greater should match when target > criteria")
	}
}




// TestMatchSubsetComprehensive tests matchSubset with more branch coverage
func TestMatchSubsetComprehensive(t *testing.T) {
	options := &AdvancedMatchOptions{}

	// Nil criteria
	if matchSubset(nil, &CPE{Part: *PartApplication}, options) {
		t.Error("matchSubset with nil criteria should return false")
	}

	// Nil target
	if matchSubset(&CPE{Part: *PartApplication}, nil, options) {
		t.Error("matchSubset with nil target should return false")
	}

	// Both nil
	if matchSubset(nil, nil, options) {
		t.Error("matchSubset with both nil should return false")
	}

	// Criteria with wildcard Part
	criteria := &CPE{Part: Part{ShortName: "*"}, Vendor: "microsoft", ProductName: "windows"}
	target := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows"}
	if !matchSubset(criteria, target, options) {
		t.Error("matchSubset with wildcard Part should pass")
	}

	// Criteria with empty Part
	criteria2 := &CPE{Part: Part{}, Vendor: "microsoft", ProductName: "windows"}
	if !matchSubset(criteria2, target, options) {
		t.Error("matchSubset with empty Part should pass")
	}

	// Mismatched Part
	criteria3 := &CPE{Part: *PartHardware, Vendor: "microsoft", ProductName: "windows"}
	if matchSubset(criteria3, target, options) {
		t.Error("matchSubset with mismatched Part should return false")
	}

	// Mismatched Vendor
	criteria4 := &CPE{Part: *PartApplication, Vendor: "google", ProductName: "windows"}
	if matchSubset(criteria4, target, options) {
		t.Error("matchSubset with mismatched Vendor should return false")
	}

	// Mismatched ProductName
	criteria5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "linux"}
	if matchSubset(criteria5, target, options) {
		t.Error("matchSubset with mismatched ProductName should return false")
	}

	// Version matching - both specific and matching
	criteria7 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	target7 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchSubset(criteria7, target7, options) {
		t.Error("matchSubset with matching versions should return true")
	}

	// Version criteria wildcard
	criteria8 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*"}
	target8 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchSubset(criteria8, target8, options) {
		t.Error("matchSubset with criteria version=* should pass")
	}

	// Non-common fields matching
	criteria11 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	target11 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	options11 := &AdvancedMatchOptions{MatchCommonOnly: false}
	if !matchSubset(criteria11, target11, options11) {
		t.Error("matchSubset with matching non-common fields should return true")
	}

	// Update mismatch
	criteria12 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp2",
	}
	if matchSubset(criteria12, target11, options11) {
		t.Error("matchSubset with Update mismatch should return false")
	}

	// Edition mismatch
	criteria13 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Edition: "home",
	}
	if matchSubset(criteria13, target11, options11) {
		t.Error("matchSubset with Edition mismatch should return false")
	}

	// Language mismatch
	criteria14 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "fr",
	}
	target14 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "en",
	}
	if matchSubset(criteria14, target14, options11) {
		t.Error("matchSubset with Language mismatch should return false")
	}

	// SoftwareEdition mismatch
	criteria15 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "enterprise",
	}
	target15 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "home",
	}
	if matchSubset(criteria15, target15, options11) {
		t.Error("matchSubset with SoftwareEdition mismatch should return false")
	}

	// TargetSoftware mismatch
	criteria16 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "linux",
	}
	target16 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "windows",
	}
	if matchSubset(criteria16, target16, options11) {
		t.Error("matchSubset with TargetSoftware mismatch should return false")
	}

	// TargetHardware mismatch
	criteria17 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "arm",
	}
	target17 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "x86",
	}
	if matchSubset(criteria17, target17, options11) {
		t.Error("matchSubset with TargetHardware mismatch should return false")
	}

	// Other mismatch
	criteria18 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom1",
	}
	target18 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom2",
	}
	if matchSubset(criteria18, target18, options11) {
		t.Error("matchSubset with Other mismatch should return false")
	}
}

// TestMatchSupersetComprehensive tests matchSuperset with more branch coverage
func TestMatchSupersetComprehensive(t *testing.T) {
	options := &AdvancedMatchOptions{}

	// Nil criteria
	if matchSuperset(nil, &CPE{Part: *PartApplication}, options) {
		t.Error("matchSuperset with nil criteria should return false")
	}

	// Nil target
	if matchSuperset(&CPE{Part: *PartApplication}, nil, options) {
		t.Error("matchSuperset with nil target should return false")
	}

	// Matching common fields - target has specific Part
	criteria := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	target := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchSuperset(criteria, target, options) {
		t.Error("matchSuperset with matching fields should return true")
	}

	// Mismatched Part
	criteria3 := &CPE{Part: *PartHardware, Vendor: "microsoft", ProductName: "windows", Version: "*"}
	target3 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if matchSuperset(criteria3, target3, options) {
		t.Error("matchSuperset with mismatched Part should return false")
	}

	// Mismatched Vendor
	criteria4 := &CPE{Part: *PartApplication, Vendor: "google", ProductName: "windows", Version: "*"}
	if matchSuperset(criteria4, target3, options) {
		t.Error("matchSuperset with mismatched Vendor should return false")
	}

	// Mismatched ProductName
	criteria5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "linux", Version: "*"}
	if matchSuperset(criteria5, target3, options) {
		t.Error("matchSuperset with mismatched ProductName should return false")
	}

	// Criteria version empty when target has specific version - superset requires criteria to also have specific version
	criteria6 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: ""}
	if matchSuperset(criteria6, target3, options) {
		t.Error("matchSuperset with empty criteria version and specific target version should return false")
	}

	// Criteria version wildcard when target has specific version
	criteria7 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "*"}
	if matchSuperset(criteria7, target3, options) {
		t.Error("matchSuperset with wildcard criteria version and specific target version should return false")
	}

	// Non-common fields matching
	criteria12 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	target12 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	options12 := &AdvancedMatchOptions{MatchCommonOnly: false}
	if !matchSuperset(criteria12, target12, options12) {
		t.Error("matchSuperset with matching non-common fields should return true")
	}

	// Update mismatch
	criteria13 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp2",
	}
	if matchSuperset(criteria13, target12, options12) {
		t.Error("matchSuperset with Update mismatch should return false")
	}

	// Edition mismatch
	criteria14 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Edition: "home",
	}
	if matchSuperset(criteria14, target12, options12) {
		t.Error("matchSuperset with Edition mismatch should return false")
	}

	// Language mismatch
	criteria15 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "fr",
	}
	target15 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "en",
	}
	if matchSuperset(criteria15, target15, options12) {
		t.Error("matchSuperset with Language mismatch should return false")
	}

	// SoftwareEdition mismatch
	criteria16 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "enterprise",
	}
	target16 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "home",
	}
	if matchSuperset(criteria16, target16, options12) {
		t.Error("matchSuperset with SoftwareEdition mismatch should return false")
	}

	// TargetSoftware mismatch
	criteria17 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "linux",
	}
	target17 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "windows",
	}
	if matchSuperset(criteria17, target17, options12) {
		t.Error("matchSuperset with TargetSoftware mismatch should return false")
	}

	// TargetHardware mismatch
	criteria18 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "arm",
	}
	target18 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "x86",
	}
	if matchSuperset(criteria18, target18, options12) {
		t.Error("matchSuperset with TargetHardware mismatch should return false")
	}

	// Other mismatch
	criteria19 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom1",
	}
	target19 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom2",
	}
	if matchSuperset(criteria19, target19, options12) {
		t.Error("matchSuperset with Other mismatch should return false")
	}

	// Target with empty/wildcard Part - should skip that check
	target20 := &CPE{Part: Part{}, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	criteria20 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchSuperset(criteria20, target20, options) {
		t.Error("matchSuperset with empty target Part should pass")
	}

	// Target with wildcard Part - should skip that check
	target21 := &CPE{Part: Part{ShortName: "*"}, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	if !matchSuperset(criteria20, target21, options) {
		t.Error("matchSuperset with wildcard target Part should pass")
	}
}


// TestMatchDistanceComprehensive tests matchDistance with proper scoring behavior
func TestMatchDistanceComprehensive(t *testing.T) {
	// All fields matching (score=1.0, threshold=0, should return true)
	criteria := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	target := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	if !matchDistance(criteria, target, &AdvancedMatchOptions{MatchCommonOnly: false, ScoreThreshold: 0.5}) {
		t.Error("matchDistance with all matching fields should return true")
	}

	// Some mismatches but score still above threshold
	criteria2 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "9"}
	target2 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	// Part(1.0) + Vendor(1.0) + Product(1.0) + Version(0.8) = 3.8, matched = Part+Vendor+Product = 3.0
	// score = 3.0/3.8 = 0.789 >= 0.5, so true
	if !matchDistance(criteria2, target2, &AdvancedMatchOptions{MatchCommonOnly: true, ScoreThreshold: 0.5}) {
		t.Error("matchDistance with score above threshold should return true")
	}

	// Score below threshold
	if matchDistance(criteria2, target2, &AdvancedMatchOptions{MatchCommonOnly: true, ScoreThreshold: 0.99}) {
		t.Error("matchDistance with score below threshold should return false")
	}

	// Required field mismatch forces return false
	criteria3 := &CPE{Part: *PartApplication, Vendor: "google", ProductName: "windows", Version: "10"}
	target3 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options3 := &AdvancedMatchOptions{
		MatchCommonOnly: true,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"vendor": {Required: true, Weight: 1.0},
		},
	}
	if matchDistance(criteria3, target3, options3) {
		t.Error("matchDistance with required field mismatch should return false")
	}

	// Required version field mismatch
	criteria4 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "9"}
	target4 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options4 := &AdvancedMatchOptions{
		MatchCommonOnly:   true,
		ScoreThreshold:    0.0,
		VersionCompareMode: "exact",
		FieldOptions: map[string]FieldMatchOption{
			"version": {Required: true, Weight: 0.8},
		},
	}
	if matchDistance(criteria4, target4, options4) {
		t.Error("matchDistance with required version mismatch should return false")
	}

	// Required version with compare mode mismatch
	criteria5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "11"}
	target5 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options5 := &AdvancedMatchOptions{
		MatchCommonOnly:   true,
		ScoreThreshold:    0.0,
		VersionCompareMode: "greater",
		FieldOptions: map[string]FieldMatchOption{
			"version": {Required: true, Weight: 0.8},
		},
	}
	// compareVersions with "greater" mode: target(10) > criteria(11)? No. Returns false.
	if matchDistance(criteria5, target5, options5) {
		t.Error("matchDistance with required version compare mismatch should return false")
	}

	// Non-common fields with required field
	criteria6 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp2", Edition: "pro",
	}
	target6 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Update: "sp1", Edition: "pro",
	}
	options6 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"update": {Required: true, Weight: 0.6},
		},
	}
	if matchDistance(criteria6, target6, options6) {
		t.Error("matchDistance with required update mismatch should return false")
	}

	// Required edition mismatch
	criteria7 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Edition: "home",
	}
	target7 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Edition: "pro",
	}
	options7 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"edition": {Required: true, Weight: 0.6},
		},
	}
	if matchDistance(criteria7, target7, options7) {
		t.Error("matchDistance with required edition mismatch should return false")
	}

	// Required language mismatch
	criteria8 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "fr",
	}
	target8 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Language: "en",
	}
	options8 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"language": {Required: true, Weight: 0.4},
		},
	}
	if matchDistance(criteria8, target8, options8) {
		t.Error("matchDistance with required language mismatch should return false")
	}

	// Required SoftwareEdition mismatch
	criteria9 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "enterprise",
	}
	target9 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		SoftwareEdition: "home",
	}
	options9 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"softwareEdition": {Required: true, Weight: 0.4},
		},
	}
	if matchDistance(criteria9, target9, options9) {
		t.Error("matchDistance with required SoftwareEdition mismatch should return false")
	}

	// Required TargetSoftware mismatch
	criteria10 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "linux",
	}
	target10 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetSoftware: "windows",
	}
	options10 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"targetSoftware": {Required: true, Weight: 0.4},
		},
	}
	if matchDistance(criteria10, target10, options10) {
		t.Error("matchDistance with required TargetSoftware mismatch should return false")
	}

	// Required TargetHardware mismatch
	criteria11 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "arm",
	}
	target11 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		TargetHardware: "x86",
	}
	options11 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"targetHardware": {Required: true, Weight: 0.4},
		},
	}
	if matchDistance(criteria11, target11, options11) {
		t.Error("matchDistance with required TargetHardware mismatch should return false")
	}

	// Required Other mismatch
	criteria12 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom1",
	}
	target12 := &CPE{
		Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10",
		Other: "custom2",
	}
	options12 := &AdvancedMatchOptions{
		MatchCommonOnly: false,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"other": {Required: true, Weight: 0.2},
		},
	}
	if matchDistance(criteria12, target12, options12) {
		t.Error("matchDistance with required Other mismatch should return false")
	}

	// Required Part mismatch
	criteria13 := &CPE{Part: *PartHardware, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	target13 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options13 := &AdvancedMatchOptions{
		MatchCommonOnly: true,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"part": {Required: true, Weight: 1.0},
		},
	}
	if matchDistance(criteria13, target13, options13) {
		t.Error("matchDistance with required Part mismatch should return false")
	}

	// Product mismatch with required field
	criteria14 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "linux", Version: "10"}
	target14 := &CPE{Part: *PartApplication, Vendor: "microsoft", ProductName: "windows", Version: "10"}
	options14 := &AdvancedMatchOptions{
		MatchCommonOnly: true,
		ScoreThreshold:  0.0,
		FieldOptions: map[string]FieldMatchOption{
			"product": {Required: true, Weight: 1.0},
		},
	}
	if matchDistance(criteria14, target14, options14) {
		t.Error("matchDistance with required Product mismatch should return false")
	}
}

// TestMatchWithRegex_PartMismatch tests that matchWithRegex returns false when Part doesn't match
func TestMatchWithRegex_PartMismatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartHardware,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	if matchWithRegex(criteria, target, options) {
		t.Error("matchWithRegex should return false when Part doesn't match")
	}
}

// TestMatchPartial_PartMismatch tests that matchPartial returns false when Part doesn't match
func TestMatchPartial_PartMismatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartHardware,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	if matchPartial(criteria, target, options) {
		t.Error("matchPartial should return false when Part doesn't match")
	}
}

// TestMatchPartial_VendorMismatch tests that matchPartial returns false when Vendor doesn't match
func TestMatchPartial_VendorMismatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("nginx"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	if matchPartial(criteria, target, options) {
		t.Error("matchPartial should return false when Vendor doesn't match")
	}
}

// TestMatchPartial_ProductMismatch tests that matchPartial returns false when ProductName doesn't match
func TestMatchPartial_ProductMismatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("httpd"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	if matchPartial(criteria, target, options) {
		t.Error("matchPartial should return false when ProductName doesn't match")
	}
}

// TestMatchPartial_VersionCompareMode tests matchPartial with non-exact VersionCompareMode
func TestMatchPartial_VersionCompareMode(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("9"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	options.VersionCompareMode = "greater"
	if matchPartial(criteria, target, options) {
		t.Error("matchPartial with version compare mode 'greater' should return false when criteria version > target")
	}
}

// TestMatchDistance_VersionMatchNonExact tests matchDistance with a version match in non-exact mode
func TestMatchDistance_VersionMatchNonExact(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := &AdvancedMatchOptions{
		VersionCompareMode: "greater",
		ScoreThreshold:     0.0,
	}
	// When versions match, the score should be > 0
	result := matchDistance(criteria, target, options)
	if !result {
		t.Error("matchDistance should return true when all fields match in non-exact version mode")
	}
}

	// TestMatchWithRegex_CoverageGap_RegexEditionMismatch tests matchWithRegex returning false on Edition mismatch
	func TestMatchWithRegex_CoverageGap_RegexEditionMismatch(t *testing.T) {
		criteria := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Edition:     "home",
		}
		target := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Edition:     "professional",
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with Edition mismatch should return false")
		}
	}

	// TestMatchWithRegex_CoverageGap_RegexLanguageMismatch tests matchWithRegex returning false on Language mismatch
	func TestMatchWithRegex_CoverageGap_RegexLanguageMismatch(t *testing.T) {
		criteria := &CPE{
			Part:     *PartApplication,
			Vendor:   "microsoft",
			ProductName: "windows",
			Version:  "10",
			Update:   "*",
			Edition:  "*",
			Language: "fr",
		}
		target := &CPE{
			Part:     *PartApplication,
			Vendor:   "microsoft",
			ProductName: "windows",
			Version:  "10",
			Update:   "sp1",
			Edition:  "pro",
			Language: "en",
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with Language mismatch should return false")
		}
	}

	// TestMatchWithRegex_CoverageGap_RegexSoftwareEditionMismatch tests matchWithRegex returning false on SoftwareEdition mismatch
	func TestMatchWithRegex_CoverageGap_RegexSoftwareEditionMismatch(t *testing.T) {
		criteria := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "*",
			Edition:         "*",
			Language:        "*",
			SoftwareEdition: "enterprise",
		}
		target := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "sp1",
			Edition:         "pro",
			Language:        "en",
			SoftwareEdition: "home",
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with SoftwareEdition mismatch should return false")
		}
	}

	// TestMatchWithRegex_CoverageGap_RegexTargetSoftwareMismatch tests matchWithRegex returning false on TargetSoftware mismatch
	func TestMatchWithRegex_CoverageGap_RegexTargetSoftwareMismatch(t *testing.T) {
		criteria := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "*",
			Edition:         "*",
			Language:        "*",
			SoftwareEdition: "*",
			TargetSoftware:  "linux",
		}
		target := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "sp1",
			Edition:         "pro",
			Language:        "en",
			SoftwareEdition: "enterprise",
			TargetSoftware:  "windows",
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with TargetSoftware mismatch should return false")
		}
	}

	// TestMatchWithRegex_CoverageGap_RegexTargetHardwareMismatch tests matchWithRegex returning false on TargetHardware mismatch
	func TestMatchWithRegex_CoverageGap_RegexTargetHardwareMismatch(t *testing.T) {
		criteria := &CPE{
			Part:            *PartApplication,
			Vendor:          "microsoft",
			ProductName:     "windows",
			Version:         "10",
			Update:          "*",
			Edition:         "*",
			Language:        "*",
			SoftwareEdition: "*",
			TargetSoftware:  "*",
			TargetHardware:  "arm",
		}
		target := &CPE{
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
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with TargetHardware mismatch should return false")
		}
	}

	// TestMatchWithRegex_CoverageGap_RegexOtherMismatch tests matchWithRegex returning false on Other mismatch
	func TestMatchWithRegex_CoverageGap_RegexOtherMismatch(t *testing.T) {
		criteria := &CPE{
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
			Other:           "custom1",
		}
		target := &CPE{
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
			Other:           "custom2",
		}
		options := &AdvancedMatchOptions{
			UseRegex:        true,
			MatchCommonOnly: false,
		}
		if matchWithRegex(criteria, target, options) {
			t.Error("matchWithRegex with Other mismatch should return false")
		}
	}

	// TestMatchPartial_CoverageGap_VersionCompareFails tests matchPartial where version compare fails
	func TestMatchPartial_CoverageGap_VersionCompareFails(t *testing.T) {
		criteria := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "11",
		}
		target := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
		}
		options := &AdvancedMatchOptions{
			PartialMatch:       true,
			VersionCompareMode: "greater",
		}
		if matchPartial(criteria, target, options) {
			t.Error("matchPartial with version compare greater failing should return false")
		}
	}

	// TestMatchPartial_CoverageGap_UpdateMismatchNonCommon tests matchPartial update mismatch in non-common fields
	func TestMatchPartial_CoverageGap_UpdateMismatchNonCommon(t *testing.T) {
		criteria := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "*",
			Update:      "sp2",
		}
		target := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Update:      "sp1",
		}
		options := &AdvancedMatchOptions{
			PartialMatch:    true,
			MatchCommonOnly: false,
		}
		if matchPartial(criteria, target, options) {
			t.Error("matchPartial with Update mismatch in non-common fields should return false")
		}
	}

	// TestMatchDistance_CoverageGap_VersionCompareNonExactMatch tests matchDistance with non-exact version compare that matches
	func TestMatchDistance_CoverageGap_VersionCompareNonExactMatch(t *testing.T) {
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
			Version:     "11",
		}
		options := &AdvancedMatchOptions{
			ScoreThreshold:     0.5,
			VersionCompareMode: "greater",
			MatchCommonOnly:    true,
			FieldOptions:       make(map[string]FieldMatchOption),
		}
		if !matchDistance(criteria, target, options) {
			t.Error("matchDistance with version compare greater should match when target version is greater")
		}
	}

	// TestMatchDistance_CoverageGap_VersionCompareNonExactRequiredMismatch tests matchDistance with non-exact version compare that fails required
	func TestMatchDistance_CoverageGap_VersionCompareNonExactRequiredMismatch(t *testing.T) {
		criteria := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "11",
		}
		target := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
		}
		options := &AdvancedMatchOptions{
			ScoreThreshold:     0.0,
			VersionCompareMode: "greater",
			MatchCommonOnly:    true,
			FieldOptions: map[string]FieldMatchOption{
				"version": {Required: true, Weight: 0.8},
			},
		}
		if matchDistance(criteria, target, options) {
			t.Error("matchDistance with required version compare greater failing should return false")
		}
	}

// TestMatchDistance_ExactVersionMatch tests matchDistance with VersionCompareMode="exact" and matching versions
func TestMatchDistance_ExactVersionMatch(t *testing.T) {
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	target := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Version:     Version("8"),
	}
	options := NewAdvancedMatchOptions()
	options.ScoreThreshold = 0.0
	// Default VersionCompareMode is "exact" - this should cover the else-branch at line 739
	result := matchDistance(criteria, target, options)
	if !result {
		t.Error("matchDistance with exact version mode and matching versions should return true")
	}
}
