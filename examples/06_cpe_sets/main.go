package main

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/scagogogo/cpe"
)

// CPESet 表示CPE对象的集合
type CPESet struct {
	cpes []*cpe.CPE
}

// NewCPESet 创建一个新的CPE集合
func NewCPESet() *CPESet {
	return &CPESet{
		cpes: make([]*cpe.CPE, 0),
	}
}

// Add 添加一个CPE到集合
func (s *CPESet) Add(cpe *cpe.CPE) {
	// 检查是否已存在
	for _, c := range s.cpes {
		if c.GetURI() == cpe.GetURI() {
			return // 已存在，不重复添加
		}
	}
	s.cpes = append(s.cpes, cpe)
}

// Remove 从集合中移除CPE
func (s *CPESet) Remove(cpe *cpe.CPE) bool {
	for i, c := range s.cpes {
		if c.GetURI() == cpe.GetURI() {
			// 移除元素
			s.cpes = append(s.cpes[:i], s.cpes[i+1:]...)
			return true
		}
	}
	return false
}

// Contains 检查集合是否包含特定CPE
func (s *CPESet) Contains(cpe *cpe.CPE) bool {
	for _, c := range s.cpes {
		if c.GetURI() == cpe.GetURI() {
			return true
		}
	}
	return false
}

// Size 返回集合大小
func (s *CPESet) Size() int {
	return len(s.cpes)
}

// Filter 根据条件过滤集合
func (s *CPESet) Filter(criteria *cpe.CPE, options *cpe.MatchOptions) *CPESet {
	result := NewCPESet()
	for _, c := range s.cpes {
		if cpe.MatchCPE(criteria, c, options) {
			result.Add(c)
		}
	}
	return result
}

// Union 合并两个集合
func (s *CPESet) Union(other *CPESet) *CPESet {
	result := NewCPESet()
	// 添加当前集合的所有元素
	for _, c := range s.cpes {
		result.Add(c)
	}
	// 添加另一个集合的所有元素
	for _, c := range other.cpes {
		result.Add(c)
	}
	return result
}

// Intersection 计算两个集合的交集
func (s *CPESet) Intersection(other *CPESet) *CPESet {
	result := NewCPESet()
	// 添加同时存在于两个集合的元素
	for _, c := range s.cpes {
		if other.Contains(c) {
			result.Add(c)
		}
	}
	return result
}

// Difference 计算集合差集 (s - other)
func (s *CPESet) Difference(other *CPESet) *CPESet {
	result := NewCPESet()
	// 添加存在于当前集合但不存在于另一个集合的元素
	for _, c := range s.cpes {
		if !other.Contains(c) {
			result.Add(c)
		}
	}
	return result
}

// String 返回集合的字符串表示
func (s *CPESet) String() string {
	if len(s.cpes) == 0 {
		return "CPESet{}"
	}

	// 获取所有CPE的URI并排序
	uris := make([]string, len(s.cpes))
	for i, c := range s.cpes {
		uris[i] = c.GetURI()
	}
	sort.Strings(uris)

	return fmt.Sprintf("CPESet{%s}", strings.Join(uris, ", "))
}

func main() {
	// CPE集合操作示例
	// 展示如何创建和操作CPE集合

	fmt.Println("========= CPE集合操作示例 =========")

	// 示例1: 创建CPE集合
	fmt.Println("\n===== 示例1: 创建CPE集合 =====")

	// 创建一些CPE对象
	cpeWin10, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 10 CPE失败: %v", err)
	}

	cpeWin11, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Windows 11 CPE失败: %v", err)
	}

	cpeAcrobat, err := cpe.ParseCpe23("cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Acrobat Reader CPE失败: %v", err)
	}

	cpeJava8, err := cpe.ParseCpe23("cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Java 8 CPE失败: %v", err)
	}

	cpeJava11, err := cpe.ParseCpe23("cpe:2.3:a:oracle:java:11.0.0:*:*:*:*:*:*:*")
	if err != nil {
		log.Fatalf("解析Java 11 CPE失败: %v", err)
	}

	// 创建一个CPE集合
	microsoftSet := NewCPESet()
	microsoftSet.Add(cpeWin10)
	microsoftSet.Add(cpeWin11)

	// 创建另一个CPE集合
	oracleSet := NewCPESet()
	oracleSet.Add(cpeJava8)
	oracleSet.Add(cpeJava11)

	// 创建第三个CPE集合
	mixedSet := NewCPESet()
	mixedSet.Add(cpeWin10)
	mixedSet.Add(cpeJava8)
	mixedSet.Add(cpeAcrobat)

	// 显示各个集合
	fmt.Printf("Microsoft集合: %s\n", microsoftSet)
	fmt.Printf("Oracle集合: %s\n", oracleSet)
	fmt.Printf("混合集合: %s\n", mixedSet)

	/*
		输出示例:
		===== 示例1: 创建CPE集合 =====
		Microsoft集合: CPESet{cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*}
		Oracle集合: CPESet{cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:11.0.0:*:*:*:*:*:*:*}
		混合集合: CPESet{cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*}
	*/

	// 示例2: 基本集合操作
	fmt.Println("\n===== 示例2: 基本集合操作 =====")

	// 添加操作
	microsoftSet.Add(cpeWin10) // 尝试添加已存在的元素
	fmt.Printf("添加已存在元素后的Microsoft集合大小: %d\n", microsoftSet.Size())

	// 移除操作
	removed := mixedSet.Remove(cpeJava8)
	fmt.Printf("从混合集合移除Java 8: %t\n", removed)
	fmt.Printf("移除后的混合集合: %s\n", mixedSet)

	// 包含检查
	fmt.Printf("Microsoft集合包含Windows 10: %t\n", microsoftSet.Contains(cpeWin10))
	fmt.Printf("Microsoft集合包含Java 8: %t\n", microsoftSet.Contains(cpeJava8))

	/*
		输出示例:
		===== 示例2: 基本集合操作 =====
		添加已存在元素后的Microsoft集合大小: 2
		从混合集合移除Java 8: true
		移除后的混合集合: CPESet{cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*}
		Microsoft集合包含Windows 10: true
		Microsoft集合包含Java 8: false
	*/

	// 示例3: 集合过滤
	fmt.Println("\n===== 示例3: 集合过滤 =====")

	// 创建一个更大的集合
	allSet := NewCPESet()
	allSet.Add(cpeWin10)
	allSet.Add(cpeWin11)
	allSet.Add(cpeJava8)
	allSet.Add(cpeJava11)
	allSet.Add(cpeAcrobat)

	// 创建过滤条件
	microsoftCriteria := &cpe.CPE{
		Part:        *cpe.PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
	}

	// 过滤集合
	microsoftFiltered := allSet.Filter(microsoftCriteria, nil)
	fmt.Printf("所有CPE: %s\n", allSet)
	fmt.Printf("过滤后的Microsoft CPE: %s\n", microsoftFiltered)

	// 创建版本范围过滤条件
	versionOptions := &cpe.MatchOptions{
		VersionRange: true,
		MinVersion:   "10",
		MaxVersion:   "10",
	}

	// 过滤指定版本的Windows
	win10Filtered := allSet.Filter(microsoftCriteria, versionOptions)
	fmt.Printf("Windows 10过滤结果: %s\n", win10Filtered)

	/*
		输出示例:
		===== 示例3: 集合过滤 =====
		所有CPE: CPESet{cpe:2.3:a:adobe:acrobat_reader:dc:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:11.0.0:*:*:*:*:*:*:*}
		过滤后的Microsoft CPE: CPESet{cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*}
		Windows 10过滤结果: CPESet{cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*}
	*/

	// 示例4: 集合运算
	fmt.Println("\n===== 示例4: 集合运算 =====")

	// 集合并集
	unionSet := microsoftSet.Union(oracleSet)
	fmt.Printf("Microsoft集合 ∪ Oracle集合: %s\n", unionSet)

	// 集合交集
	mixedSet.Add(cpeJava8) // 添加回Java 8
	intersectionSet := mixedSet.Intersection(oracleSet)
	fmt.Printf("混合集合 ∩ Oracle集合: %s\n", intersectionSet)

	// 集合差集
	differenceSet := unionSet.Difference(mixedSet)
	fmt.Printf("(Microsoft集合 ∪ Oracle集合) - 混合集合: %s\n", differenceSet)

	/*
		输出示例:
		===== 示例4: 集合运算 =====
		Microsoft集合 ∪ Oracle集合: CPESet{cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*, cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:11.0.0:*:*:*:*:*:*:*}
		混合集合 ∩ Oracle集合: CPESet{cpe:2.3:a:oracle:java:1.8.0:*:*:*:*:*:*:*}
		(Microsoft集合 ∪ Oracle集合) - 混合集合: CPESet{cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*, cpe:2.3:a:oracle:java:11.0.0:*:*:*:*:*:*:*}
	*/
}
