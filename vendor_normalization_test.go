package cpeskills

import "testing"

func TestAreSameProduct(t *testing.T) {
	n := NewVendorNormalizer()
	// windows_10 是 windows 的别名 → 相同
	if !n.AreSameProduct("microsoft", "windows_10", "windows") {
		t.Error("expected windows_10 == windows")
	}
	// 不同产品
	if n.AreSameProduct("microsoft", "windows", "office") {
		t.Error("expected windows != office")
	}
}

func TestAreSameProduct_Unknown(t *testing.T) {
	n := NewVendorNormalizer()
	// 未知产品，规范化后比较
	if !n.AreSameProduct("vendor", "My Product", "my_product") {
		t.Error("expected My Product == my_product (normalized)")
	}
}

func TestNormalizeProductName_Global(t *testing.T) {
	// 全局便捷函数
	got := NormalizeProductName("microsoft", "windows_10")
	if got != "windows" {
		t.Errorf("expected windows, got %q", got)
	}
}

func TestNormalizeCPEVendorProduct_Global(t *testing.T) {
	cpe := mustParseCPE(t, "cpe:2.3:a:microsoft:windows_10:1:*:*:*:*:*:*:*")
	got := NormalizeCPEVendorProduct(cpe)
	if string(got.ProductName) != "windows" {
		t.Errorf("expected product windows, got %q", got.ProductName)
	}
	if string(got.Vendor) != "microsoft" {
		t.Errorf("expected vendor microsoft, got %q", got.Vendor)
	}
}

func TestNormalizeCPEVendorProduct_Nil(t *testing.T) {
	if got := NormalizeCPEVendorProduct(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestNormalizeCPE_Nil(t *testing.T) {
	n := NewVendorNormalizer()
	if got := n.NormalizeCPE(nil); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}
