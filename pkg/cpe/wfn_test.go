package cpeskills

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

// TestToCPEDefaultPart 测试WFN转CPE时无效Part默认为Application
func TestToCPEDefaultPart(t *testing.T) {
	wfn := &WFN{
		Part:    "x",
		Vendor:  "test",
		Product: "product",
		Version: "1.0",
	}
	cpe := wfn.ToCPE()
	if cpe.Part.ShortName != "a" {
		t.Errorf("Invalid part should default to 'a', got %q", cpe.Part.ShortName)
	}
}

// TestToCPEHardwarePart 测试WFN转CPE硬件类型
func TestToCPEHardwarePart(t *testing.T) {
	wfn := &WFN{
		Part:    "h",
		Vendor:  "intel",
		Product: "core_i7",
		Version: "1068g7",
	}
	cpe := wfn.ToCPE()
	if cpe.Part.ShortName != "h" {
		t.Errorf("Part = %q, want %q", cpe.Part.ShortName, "h")
	}
}
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

// TestWFNMatchEdgeCases tests additional edge cases for WFN Match
func TestWFNMatchEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		wfn1     *WFN
		wfn2     *WFN
		expected bool
	}{
		{
			name: "mismatch on Part",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			wfn2: &WFN{
				Part:    "o",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "10",
			},
			expected: false,
		},
		{
			name: "match with wildcard Part",
			wfn1: &WFN{
				Part:    "*",
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
			name: "mismatch on empty Part vs specific",
			wfn1: &WFN{
				Part:    "",
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
			expected: false,
		},
		{
			name: "match with all ANY in wfn1",
			wfn1: &WFN{
				Part:    "*",
				Vendor:  "*",
				Product: "*",
				Version: "*",
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
			name: "match with both NA version",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "-",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "-",
			},
			expected: true,
		},
		{
			name: "no match with NA version vs specific version",
			wfn1: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
				Version: "-",
			},
			wfn2: &WFN{
				Part:    "a",
				Vendor:  "microsoft",
				Product: "windows",
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
			expected: "product%3aname",
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

// TestWFNMatchExtendedAttributes 测试WFN Match的扩展属性匹配
func TestWFNMatchExtendedAttributes(t *testing.T) {
	// Test NA values matching
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

	// Test NA vs specific version
	wfn3 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
	}
	if wfn1.Match(wfn3) {
		t.Error("Expected NA and specific version not to match")
	}

	// Test mismatch on Update
	wfn4 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Update:  "sp1",
	}
	wfn5 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Update:  "sp2",
	}
	if wfn4.Match(wfn5) {
		t.Error("Expected different Update values not to match")
	}

	// Test mismatch on Edition
	wfn6 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Edition: "pro",
	}
	wfn7 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Edition: "home",
	}
	if wfn6.Match(wfn7) {
		t.Error("Expected different Edition values not to match")
	}

	// Test mismatch on Language
	wfn8 := &WFN{
		Part:     "a",
		Vendor:   "microsoft",
		Product:  "windows",
		Version:  "10",
		Language: "en",
	}
	wfn9 := &WFN{
		Part:     "a",
		Vendor:   "microsoft",
		Product:  "windows",
		Version:  "10",
		Language: "de",
	}
	if wfn8.Match(wfn9) {
		t.Error("Expected different Language values not to match")
	}

	// Test wildcard on Update
	wfn10 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Update:  "*",
	}
	wfn11 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Update:  "sp1",
	}
	if !wfn10.Match(wfn11) {
		t.Error("Expected ANY Update to match specific Update")
	}

	// Test mismatch on SoftwareEdition
	wfn12 := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		SoftwareEdition: "enterprise",
	}
	wfn13 := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		SoftwareEdition: "standard",
	}
	if wfn12.Match(wfn13) {
		t.Error("Expected different SoftwareEdition values not to match")
	}

	// Test mismatch on TargetSoftware
	wfn14 := &WFN{
		Part:           "a",
		Vendor:         "microsoft",
		Product:        "windows",
		Version:        "10",
		TargetSoftware: "linux",
	}
	wfn15 := &WFN{
		Part:           "a",
		Vendor:         "microsoft",
		Product:        "windows",
		Version:        "10",
		TargetSoftware: "windows",
	}
	if wfn14.Match(wfn15) {
		t.Error("Expected different TargetSoftware values not to match")
	}

	// Test mismatch on TargetHardware
	wfn16 := &WFN{
		Part:           "a",
		Vendor:         "microsoft",
		Product:        "windows",
		Version:        "10",
		TargetHardware: "x86",
	}
	wfn17 := &WFN{
		Part:           "a",
		Vendor:         "microsoft",
		Product:        "windows",
		Version:        "10",
		TargetHardware: "arm",
	}
	if wfn16.Match(wfn17) {
		t.Error("Expected different TargetHardware values not to match")
	}

	// Test mismatch on Other
	wfn18 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Other:   "custom1",
	}
	wfn19 := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
		Other:   "custom2",
	}
	if wfn18.Match(wfn19) {
		t.Error("Expected different Other values not to match")
	}
}
