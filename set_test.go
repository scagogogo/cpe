package cpe

import (
	"strings"
	"testing"
)

func createTestCPE(cpe23 string, part Part, vendor string, product string, version string) *CPE {
	return &CPE{
		Cpe23:       cpe23,
		Part:        part,
		Vendor:      Vendor(vendor),
		ProductName: Product(product),
		Version:     Version(version),
	}
}

// TestNewCPESet 测试创建CPE集合
func TestNewCPESet(t *testing.T) {
	name := "TestSet"
	desc := "Test Description"

	set := NewCPESet(name, desc)

	if set.Name != name {
		t.Errorf("NewCPESet() name = %v, want %v", set.Name, name)
	}

	if set.Description != desc {
		t.Errorf("NewCPESet() description = %v, want %v", set.Description, desc)
	}

	if len(set.Items) != 0 {
		t.Errorf("NewCPESet() should create empty set, got size %v", len(set.Items))
	}
}

// TestCPESet_Add 测试添加CPE到集合
func TestCPESet_Add(t *testing.T) {
	set := NewCPESet("Test", "Test")
	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")

	// Test adding a CPE
	set.Add(cpe1)
	if !set.Contains(cpe1) {
		t.Errorf("Set should contain added CPE")
	}

	// Test adding duplicate CPE
	initialSize := set.Size()
	set.Add(cpe1)
	if set.Size() != initialSize {
		t.Errorf("Adding duplicate CPE should not increase set size")
	}

	// Test adding another CPE
	set.Add(cpe2)
	if !set.Contains(cpe2) {
		t.Errorf("Set should contain second added CPE")
	}

	// Test contains with non-present CPE
	cpe3 := createTestCPE("cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "other", "1.0")
	if set.Contains(cpe3) {
		t.Errorf("Set should not contain non-added CPE")
	}
}

// TestCPESet_Remove 测试从集合中删除CPE
func TestCPESet_Remove(t *testing.T) {
	set := NewCPESet("Test", "Test")
	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")

	set.Add(cpe1)
	set.Add(cpe2)

	// Test removing existing CPE
	removed := set.Remove(cpe1)
	if !removed || set.Contains(cpe1) {
		t.Errorf("Remove() failed to remove existing CPE")
	}

	// Test removing non-existing CPE
	removed = set.Remove(cpe1)
	if removed {
		t.Errorf("Remove() should return false for non-existing CPE")
	}
}

// TestCPESet_Contains 测试检查集合是否包含CPE
func TestCPESet_Contains(t *testing.T) {
	set := NewCPESet("Test", "Test")

	// Test contains with non-present CPE
	cpe3 := createTestCPE("cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "other", "1.0")
	if set.Contains(cpe3) {
		t.Errorf("Set should not contain non-added CPE")
	}
}

// TestCPESet_Size 测试获取集合大小
func TestCPESet_Size(t *testing.T) {
	set := NewCPESet("Test", "Test")
	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")

	// Test initial size
	if set.Size() != 0 {
		t.Errorf("Initial set size should be 0")
	}

	// Test size after adding
	set.Add(cpe1)
	set.Add(cpe2)
	if set.Size() != 2 {
		t.Errorf("Set size should be 2 after adding 2 CPEs")
	}
}

// TestCPESet_Clear 测试清空集合
func TestCPESet_Clear(t *testing.T) {
	set := NewCPESet("Test", "Test")
	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")

	// Test initial size
	if set.Size() != 0 {
		t.Errorf("Initial set size should be 0")
	}

	// Test size after adding
	set.Add(cpe1)
	set.Add(cpe2)
	if set.Size() != 2 {
		t.Errorf("Set size should be 2 after adding 2 CPEs")
	}

	// Test clear
	set.Clear()
	if set.Size() != 0 {
		t.Errorf("Set size should be 0 after clear")
	}
}

// TestCPESet_Union 测试集合并集操作
func TestCPESet_Union(t *testing.T) {
	set1 := NewCPESet("Set1", "First set")
	set2 := NewCPESet("Set2", "Second set")

	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")
	cpe3 := createTestCPE("cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "other", "1.0")

	set1.Add(cpe1)
	set1.Add(cpe2)
	set2.Add(cpe2)
	set2.Add(cpe3)

	union := set1.Union(set2)

	if union.Size() != 3 {
		t.Errorf("Union size should be 3, got %d", union.Size())
	}

	if !union.Contains(cpe1) || !union.Contains(cpe2) || !union.Contains(cpe3) {
		t.Errorf("Union should contain all CPEs from both sets")
	}
}

// TestCPESet_Intersection 测试集合交集操作
func TestCPESet_Intersection(t *testing.T) {
	set1 := NewCPESet("Set1", "First set")
	set2 := NewCPESet("Set2", "Second set")

	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")
	cpe3 := createTestCPE("cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "other", "1.0")

	set1.Add(cpe1)
	set1.Add(cpe2)
	set2.Add(cpe2)
	set2.Add(cpe3)

	intersection := set1.Intersection(set2)

	if intersection.Size() != 1 {
		t.Errorf("Intersection size should be 1, got %d", intersection.Size())
	}

	if !intersection.Contains(cpe2) {
		t.Errorf("Intersection should contain CPE2")
	}

	if intersection.Contains(cpe1) || intersection.Contains(cpe3) {
		t.Errorf("Intersection should not contain CPE1 or CPE3")
	}
}

// TestCPESet_Difference 测试集合差集操作
func TestCPESet_Difference(t *testing.T) {
	set1 := NewCPESet("Set1", "First set")
	set2 := NewCPESet("Set2", "Second set")

	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")
	cpe3 := createTestCPE("cpe:2.3:a:vendor:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "other", "1.0")

	set1.Add(cpe1)
	set1.Add(cpe2)
	set2.Add(cpe2)
	set2.Add(cpe3)

	difference := set1.Difference(set2)

	if difference.Size() != 1 {
		t.Errorf("Difference size should be 1, got %d", difference.Size())
	}

	if !difference.Contains(cpe1) {
		t.Errorf("Difference should contain CPE1")
	}

	if difference.Contains(cpe2) || difference.Contains(cpe3) {
		t.Errorf("Difference should not contain CPE2 or CPE3")
	}
}

// TestCPESet_Filter 测试过滤集合
func TestCPESet_Filter(t *testing.T) {
	set := NewCPESet("TestSet", "Test set")

	cpe1 := createTestCPE("cpe:2.3:a:vendor1:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor1", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor2:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor2", "product", "2.0")
	cpe3 := createTestCPE("cpe:2.3:a:vendor3:other:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor3", "other", "1.0")

	set.Add(cpe1)
	set.Add(cpe2)
	set.Add(cpe3)

	// Filter by product
	criteria := &CPE{
		ProductName: "product",
	}

	filtered := set.Filter(criteria, nil)

	if filtered.Size() != 2 {
		t.Errorf("Filter by product should return 2 CPEs, got %d", filtered.Size())
	}

	// Filter by vendor
	criteria = &CPE{
		Vendor: "vendor1",
	}

	filtered = set.Filter(criteria, nil)

	if filtered.Size() != 1 || !filtered.Contains(cpe1) {
		t.Errorf("Filter by vendor should return 1 CPE (cpe1)")
	}
}

// TestFromArray 测试从数组创建CPE集合
func TestFromArray(t *testing.T) {
	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")

	cpes := []*CPE{cpe1, cpe2}

	set := FromArray(cpes, "TestSet", "Created from array")

	if set.Size() != 2 {
		t.Errorf("FromArray() set should have 2 CPEs, got %d", set.Size())
	}

	if !set.Contains(cpe1) || !set.Contains(cpe2) {
		t.Errorf("FromArray() set should contain all CPEs from array")
	}

	if set.Name != "TestSet" || set.Description != "Created from array" {
		t.Errorf("FromArray() set has incorrect name or description")
	}
}

// TestFindRelated 测试查找相关CPE
func TestFindRelated(t *testing.T) {
	set := NewCPESet("TestSet", "Test set")

	cpe1 := createTestCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "1.0")
	cpe2 := createTestCPE("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*", *PartApplication, "vendor", "product", "2.0")
	cpe3 := createTestCPE("cpe:2.3:a:othervendor:product:1.0:*:*:*:*:*:*:*", *PartApplication, "othervendor", "product", "1.0")

	set.Add(cpe1)
	set.Add(cpe2)
	set.Add(cpe3)

	// Find related by vendor and product
	criteria := &CPE{
		Vendor:      "vendor",
		ProductName: "product",
	}

	related := set.FindRelated(criteria, nil)

	if related.Size() != 2 {
		t.Errorf("FindRelated should return 2 CPEs, got %d", related.Size())
	}

	if !related.Contains(cpe1) || !related.Contains(cpe2) {
		t.Errorf("FindRelated should find cpe1 and cpe2")
	}
}

// Utility function to check if a string contains a substring
func contains(s, substr string) bool {
	return s != "" && substr != "" && len(s) >= len(substr) && s != substr && strings.Contains(s, substr)
}
