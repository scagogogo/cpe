package cpe

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

// TestIsRequiredField 测试字段是否必需
func TestIsRequiredField(t *testing.T) {
	tests := []struct {
		name     string
		options  *AdvancedMatchOptions
		field    string
		expected bool
	}{
		{
			name: "字段在FieldOptions中设置为必需",
			options: &AdvancedMatchOptions{
				FieldOptions: map[string]FieldMatchOption{
					"vendor": {Required: true},
				},
			},
			field:    "vendor",
			expected: true,
		},
		{
			name: "字段在FieldOptions中设置为非必需",
			options: &AdvancedMatchOptions{
				FieldOptions: map[string]FieldMatchOption{
					"edition": {Required: false},
				},
			},
			field:    "edition",
			expected: false,
		},
		{
			name: "字段不在FieldOptions中",
			options: &AdvancedMatchOptions{
				FieldOptions: map[string]FieldMatchOption{
					"vendor": {Required: true},
				},
			},
			field:    "language",
			expected: false, // 默认为非必需
		},
		{
			name: "FieldOptions为nil",
			options: &AdvancedMatchOptions{
				FieldOptions: nil,
			},
			field:    "vendor",
			expected: false, // 默认为非必需
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRequiredField(tt.options, tt.field); got != tt.expected {
				t.Errorf("isRequiredField() = %v, want %v", got, tt.expected)
			}
		})
	}
}
