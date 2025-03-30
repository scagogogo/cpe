package cpe

import (
	"testing"
)

// TestFromCPE 测试从CPE创建WFN
func TestFromCPE(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected *WFN
	}{
		{
			name: "基本CPE转换",
			cpe: &CPE{
				Cpe23:           "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
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
			expected: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Update:          "*",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
		},
		{
			name: "带特殊值的CPE转换",
			cpe: &CPE{
				Cpe23:           "cpe:2.3:o:linux:linux_kernel:5.10:-:*:*:*:*:*:*",
				Part:            *PartOperationSystem,
				Vendor:          "linux",
				ProductName:     "linux_kernel",
				Version:         "5.10",
				Update:          "-",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
			expected: &WFN{
				Part:            "o",
				Vendor:          "linux",
				Product:         "linux_kernel",
				Version:         "5.10",
				Update:          "-",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromCPE(tt.cpe)

			if got.Part != tt.expected.Part {
				t.Errorf("FromCPE().Part = %v, want %v", got.Part, tt.expected.Part)
			}
			if got.Vendor != tt.expected.Vendor {
				t.Errorf("FromCPE().Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
			}
			if got.Product != tt.expected.Product {
				t.Errorf("FromCPE().Product = %v, want %v", got.Product, tt.expected.Product)
			}
			if got.Version != tt.expected.Version {
				t.Errorf("FromCPE().Version = %v, want %v", got.Version, tt.expected.Version)
			}
			if got.Update != tt.expected.Update {
				t.Errorf("FromCPE().Update = %v, want %v", got.Update, tt.expected.Update)
			}
		})
	}
}

// TestToCPE 测试WFN转CPE
func TestToCPE(t *testing.T) {
	tests := []struct {
		name     string
		wfn      *WFN
		expected *CPE
	}{
		{
			name: "基本WFN转换",
			wfn: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Update:          "*",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
			expected: &CPE{
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
		},
		{
			name: "操作系统WFN转换",
			wfn: &WFN{
				Part:            "o",
				Vendor:          "linux",
				Product:         "linux_kernel",
				Version:         "5.10",
				Update:          "-",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
			expected: &CPE{
				Part:            *PartOperationSystem,
				Vendor:          "linux",
				ProductName:     "linux_kernel",
				Version:         "5.10",
				Update:          "-",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.wfn.ToCPE()

			if got.Part.ShortName != tt.expected.Part.ShortName {
				t.Errorf("WFN.ToCPE().Part = %v, want %v", got.Part.ShortName, tt.expected.Part.ShortName)
			}
			if got.Vendor != tt.expected.Vendor {
				t.Errorf("WFN.ToCPE().Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
			}
			if got.ProductName != tt.expected.ProductName {
				t.Errorf("WFN.ToCPE().ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
			}
			if got.Version != tt.expected.Version {
				t.Errorf("WFN.ToCPE().Version = %v, want %v", got.Version, tt.expected.Version)
			}
			if got.Update != tt.expected.Update {
				t.Errorf("WFN.ToCPE().Update = %v, want %v", got.Update, tt.expected.Update)
			}
		})
	}
}

// TestFromCPE23String 测试从CPE 2.3字符串创建WFN
func TestFromCPE23String(t *testing.T) {
	tests := []struct {
		name     string
		cpe23    string
		wantErr  bool
		expected *WFN
	}{
		{
			name:    "有效的CPE 2.3字符串",
			cpe23:   "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: false,
			expected: &WFN{
				Part:            "a",
				Vendor:          "microsoft",
				Product:         "windows",
				Version:         "10",
				Update:          "*",
				Edition:         "*",
				Language:        "*",
				SoftwareEdition: "*",
				TargetSoftware:  "*",
				TargetHardware:  "*",
				Other:           "*",
			},
		},
		{
			name:    "无效的CPE 2.3格式",
			cpe23:   "cpe:2.3:a:microsoft:windows",
			wantErr: true,
		},
		{
			name:    "无效的CPE 2.3前缀",
			cpe23:   "invalid:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FromCPE23String(tt.cpe23)
			if (err != nil) != tt.wantErr {
				t.Errorf("FromCPE23String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if got.Part != tt.expected.Part {
					t.Errorf("FromCPE23String().Part = %v, want %v", got.Part, tt.expected.Part)
				}
				if got.Vendor != tt.expected.Vendor {
					t.Errorf("FromCPE23String().Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
				}
				if got.Product != tt.expected.Product {
					t.Errorf("FromCPE23String().Product = %v, want %v", got.Product, tt.expected.Product)
				}
				if got.Version != tt.expected.Version {
					t.Errorf("FromCPE23String().Version = %v, want %v", got.Version, tt.expected.Version)
				}
			}
		})
	}
}

// TestWFNMatch 测试WFN匹配功能
func TestWFNMatch(t *testing.T) {
	tests := []struct {
		name     string
		wfn1     *WFN
		wfn2     *WFN
		expected bool
	}{
		{
			name: "完全相同的WFN应匹配",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: true,
		},
		{
			name: "通配符匹配",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "*",
			},
			expected: true,
		},
		{
			name: "不匹配的版本",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "11",
			},
			expected: false,
		},
		{
			name: "不匹配的产品",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "office",
				Version: "10",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.wfn1.Match(tt.wfn2); got != tt.expected {
				t.Errorf("WFN.Match() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestEscapeValue 测试WFN值转义
func TestEscapeValue(t *testing.T) {
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
			expected: "example\\.com",
		},
		{
			name:     "冒号需要转义",
			value:    "product:name",
			expected: "product\\:name",
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
			if got := escapeValue(tt.value); got != tt.expected {
				t.Errorf("escapeValue() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUnescapeValue 测试WFN值反转义
func TestUnescapeValue(t *testing.T) {
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
			value:    "example\\.com",
			expected: "example.com",
		},
		{
			name:     "转义的冒号",
			value:    "product\\:name",
			expected: "product:name",
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
			if got := unescapeValue(tt.value); got != tt.expected {
				t.Errorf("unescapeValue() = %v, want %v", got, tt.expected)
			}
		})
	}
}
