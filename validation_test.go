package cpe

import (
	"testing"
)

// TestValidateComponent 测试组件验证
func TestValidateComponent(t *testing.T) {
	tests := []struct {
		name          string
		value         string
		componentName string
		wantErr       bool
	}{
		{
			name:          "有效的普通值",
			value:         "windows",
			componentName: "product",
			wantErr:       false,
		},
		{
			name:          "有效的特殊字符",
			value:         "example.com",
			componentName: "vendor",
			wantErr:       false,
		},
		{
			name:          "有效的ANY值",
			value:         "*",
			componentName: "version",
			wantErr:       false,
		},
		{
			name:          "有效的NA值",
			value:         "-",
			componentName: "update",
			wantErr:       false,
		},
		{
			name:          "空值",
			value:         "",
			componentName: "edition",
			wantErr:       false,
		},
		{
			name:          "非法字符",
			value:         "product!name",
			componentName: "product",
			wantErr:       true,
		},
		{
			name:          "非法控制字符",
			value:         "product\tname",
			componentName: "product",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateComponent(tt.value, tt.componentName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateComponent() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateCPE 测试CPE验证
func TestValidateCPE(t *testing.T) {
	tests := []struct {
		name    string
		cpe     *CPE
		wantErr bool
	}{
		{
			name: "有效的CPE",
			cpe: &CPE{
				Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			wantErr: false,
		},
		{
			name: "无效的Part",
			cpe: &CPE{
				Part:        Part{ShortName: "x"},
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			wantErr: true,
		},
		{
			name: "无效的Vendor",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft!invalid",
				ProductName: "windows",
				Version:     "10",
			},
			wantErr: true,
		},
		{
			name: "无效的ProductName",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows\nbreak",
				Version:     "10",
			},
			wantErr: true,
		},
		{
			name: "部分为空的CPE",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "",
				ProductName: "windows",
				Version:     "",
			},
			wantErr: false, // 空值是允许的
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCPE(tt.cpe)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCPE() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestNormalizeComponent 测试组件标准化
func TestNormalizeComponent(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "全小写转换",
			value:    "Windows",
			expected: "windows",
		},
		{
			name:     "特殊字符保留",
			value:    "Example.com",
			expected: "example.com",
		},
		{
			name:     "空格替换",
			value:    "Windows 10",
			expected: "windows_10",
		},
		{
			name:     "多个空格替换",
			value:    "Windows  10",
			expected: "windows_10",
		},
		{
			name:     "不修改特殊值",
			value:    "*",
			expected: "*",
		},
		{
			name:     "不修改特殊值",
			value:    "-",
			expected: "-",
		},
		{
			name:     "标准化为空",
			value:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeComponent(tt.value)
			if got != tt.expected {
				t.Errorf("NormalizeComponent() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestNormalizeCPE 测试CPE标准化
func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		expected *CPE
	}{
		{
			name: "标准化所有字段",
			cpe: &CPE{
				Vendor:      "Microsoft",
				ProductName: "Windows 10",
				Version:     "2H22",
				Update:      "Latest",
			},
			expected: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows_10",
				Version:     "2h22",
				Update:      "latest",
			},
		},
		{
			name: "保留特殊值",
			cpe: &CPE{
				Vendor:      "Microsoft",
				ProductName: "Windows",
				Version:     "*",
				Update:      "-",
			},
			expected: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "*",
				Update:      "-",
			},
		},
		{
			name:     "nil CPE",
			cpe:      nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeCPE(tt.cpe)

			if tt.cpe == nil {
				if got != nil {
					t.Errorf("NormalizeCPE() = %v, want nil", got)
				}
				return
			}

			if got.Vendor != tt.expected.Vendor {
				t.Errorf("NormalizeCPE().Vendor = %v, want %v", got.Vendor, tt.expected.Vendor)
			}

			if got.ProductName != tt.expected.ProductName {
				t.Errorf("NormalizeCPE().ProductName = %v, want %v", got.ProductName, tt.expected.ProductName)
			}

			if got.Version != tt.expected.Version {
				t.Errorf("NormalizeCPE().Version = %v, want %v", got.Version, tt.expected.Version)
			}

			if got.Update != tt.expected.Update {
				t.Errorf("NormalizeCPE().Update = %v, want %v", got.Update, tt.expected.Update)
			}
		})
	}
}

// TestFSStringToURI 测试文件系统安全字符串到URI的转换
func TestFSStringToURI(t *testing.T) {
	tests := []struct {
		name     string
		fs       string
		expected string
	}{
		{
			name:     "基本转换",
			fs:       "cpe___2.3_a_microsoft_windows_10_-_-_-_-_-_-_-",
			expected: "cpe:2.3:a:microsoft:windows:10:-:-:-:-:-:-:-",
		},
		{
			name:     "保留下划线",
			fs:       "cpe___2.3_a_microsoft_windows__server_10_-_-_-_-_-_-_-",
			expected: "cpe:2.3:a:microsoft:windows_server:10:-:-:-:-:-:-:-",
		},
		{
			name:     "处理特殊字符",
			fs:       "cpe___2.3_a_example__20__com_product_1.0_-_-_-_-_-_-_-",
			expected: "cpe:2.3:a:example.com:product:1.0:-:-:-:-:-:-:-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FSStringToURI(tt.fs)
			if got != tt.expected {
				t.Errorf("FSStringToURI() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestURIToFSString 测试URI到文件系统安全字符串的转换
func TestURIToFSString(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "基本转换",
			uri:      "cpe:2.3:a:microsoft:windows:10:-:-:-:-:-:-:-",
			expected: "cpe___2.3_a_microsoft_windows_10_-_-_-_-_-_-_-",
		},
		{
			name:     "保留下划线",
			uri:      "cpe:2.3:a:microsoft:windows_server:10:-:-:-:-:-:-:-",
			expected: "cpe___2.3_a_microsoft_windows__server_10_-_-_-_-_-_-_-",
		},
		{
			name:     "处理特殊字符",
			uri:      "cpe:2.3:a:example.com:product:1.0:-:-:-:-:-:-:-",
			expected: "cpe___2.3_a_example__20__com_product_1.0_-_-_-_-_-_-_-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := URIToFSString(tt.uri)
			if got != tt.expected {
				t.Errorf("URIToFSString() = %v, want %v", got, tt.expected)
			}
		})
	}
}
