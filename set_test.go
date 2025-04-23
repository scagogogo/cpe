package cpe

import (
	"fmt"
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

	if set.Size() != 0 {
		t.Errorf("NewCPESet() should create empty set, got size %v", set.Size())
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

// TestCPESetBasicOperations 测试CPESet的基本操作
func TestCPESetBasicOperations(t *testing.T) {
	set := NewCPESet("Test Set", "A test set for testing")

	// 测试初始状态
	if set.Size() != 0 {
		t.Errorf("新集合的大小应为0，实际为%d", set.Size())
	}

	// 测试添加
	cpe1, _ := ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	cpe2, _ := ParseCpe23("cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*")
	cpe3, _ := ParseCpe23("cpe:2.3:a:apple:macos:11:*:*:*:*:*:*:*")

	set.Add(cpe1)
	set.Add(cpe2)
	set.Add(cpe3)

	if set.Size() != 3 {
		t.Errorf("添加3个CPE后大小应为3，实际为%d", set.Size())
	}

	// 测试重复添加
	set.Add(cpe1)
	if set.Size() != 3 {
		t.Errorf("添加重复CPE后大小应为3，实际为%d", set.Size())
	}

	// 测试包含
	if !set.Contains(cpe1) {
		t.Errorf("集合应包含已添加的CPE")
	}

	// 测试移除
	removed := set.Remove(cpe2)
	if !removed || set.Size() != 2 {
		t.Errorf("移除后大小应为2，实际为%d，移除状态：%v", set.Size(), removed)
	}

	// 测试移除不存在的CPE
	cpe4, _ := ParseCpe23("cpe:2.3:a:google:chrome:90:*:*:*:*:*:*:*")
	removed = set.Remove(cpe4)
	if removed {
		t.Errorf("移除不存在的CPE应返回false")
	}

	// 测试清空
	set.Clear()
	if set.Size() != 0 {
		t.Errorf("清空后大小应为0，实际为%d", set.Size())
	}
}

// TestCPESetSetOperations 测试CPESet的集合操作
func TestCPESetSetOperations(t *testing.T) {
	set1 := NewCPESet("Set1", "First set")
	set2 := NewCPESet("Set2", "Second set")

	// 添加CPE到set1
	cpe1, _ := ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	cpe2, _ := ParseCpe23("cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*")
	set1.Add(cpe1)
	set1.Add(cpe2)

	// 添加CPE到set2
	cpe3, _ := ParseCpe23("cpe:2.3:a:apple:macos:11:*:*:*:*:*:*:*")
	set2.Add(cpe2) // 与set1有一个重叠
	set2.Add(cpe3)

	// 测试并集
	union := set1.Union(set2)
	if union.Size() != 3 {
		t.Errorf("并集大小应为3，实际为%d", union.Size())
	}

	// 测试交集
	intersection := set1.Intersection(set2)
	if intersection.Size() != 1 {
		t.Errorf("交集大小应为1，实际为%d", intersection.Size())
	}

	// 测试差集
	diff1 := set1.Difference(set2)
	if diff1.Size() != 1 {
		t.Errorf("set1-set2差集大小应为1，实际为%d", diff1.Size())
	}

	diff2 := set2.Difference(set1)
	if diff2.Size() != 1 {
		t.Errorf("set2-set1差集大小应为1，实际为%d", diff2.Size())
	}
}

// BenchmarkCPESetOperations 性能测试CPESet的基本操作
func BenchmarkCPESetOperations(b *testing.B) {
	// 预生成大量CPE以用于测试
	cpes := make([]*CPE, 1000)
	for i := 0; i < 1000; i++ {
		// 创建不同的CPE
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      Vendor(fmt.Sprintf("vendor%d", i%100)),
			ProductName: Product(fmt.Sprintf("product%d", i%200)),
			Version:     Version(fmt.Sprintf("%d.0", i%50)),
		}
		cpe.Cpe23 = FormatCpe23(cpe) // 生成URI
		cpes[i] = cpe
	}

	// 基准测试：添加
	b.Run("Add", func(b *testing.B) {
		set := NewCPESet("Benchmark", "Benchmark set")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			set.Add(cpes[i%1000])
		}
	})

	// 基准测试：包含检查
	b.Run("Contains", func(b *testing.B) {
		set := NewCPESet("Benchmark", "Benchmark set")
		// 先添加一半的CPE
		for i := 0; i < 500; i++ {
			set.Add(cpes[i])
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			set.Contains(cpes[i%1000]) // 一半存在，一半不存在
		}
	})

	// 基准测试：移除
	b.Run("Remove", func(b *testing.B) {
		set := NewCPESet("Benchmark", "Benchmark set")
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 确保有足够的元素可以移除
			if i%2 == 0 {
				set.Add(cpes[i%1000])
			} else {
				set.Remove(cpes[i%1000])
			}
		}
	})

	// 基准测试：交集操作
	b.Run("Intersection", func(b *testing.B) {
		set1 := NewCPESet("Set1", "First set")
		set2 := NewCPESet("Set2", "Second set")

		// 添加CPE，两个集合有50%的重叠
		for i := 0; i < 500; i++ {
			set1.Add(cpes[i])
		}
		for i := 250; i < 750; i++ {
			set2.Add(cpes[i])
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			set1.Intersection(set2)
		}
	})
}
