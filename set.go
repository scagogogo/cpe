package cpe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scagogogo/versions"
)

/**
 * CPESet 表示CPE(通用平台枚举)元素的集合
 *
 * CPESet提供了一组用于管理和操作CPE集合的方法，包括集合运算（并集、交集、差集）、
 * 过滤、排序等。这对于处理大量CPE数据、分组分析和漏洞影响范围评估非常有用。
 *
 * 集合中的每个CPE元素都是唯一的，基于Cpe23字段进行重复检测。
 */
type CPESet struct {
	// Items 存储集合中的所有CPE对象
	Items []*CPE

	// Name 集合的名称，用于标识和区分不同集合
	Name string

	// Description 集合的详细描述
	Description string
}

/**
 * NewCPESet 创建一个新的CPE集合
 *
 * @param name string 集合的名称
 * @param description string 集合的描述
 * @return *CPESet 新创建的CPE集合
 *
 * 示例:
 *   ```go
 *   // 创建一个包含Microsoft产品的CPE集合
 *   microsoftSet := cpe.NewCPESet("Microsoft Products", "Collection of Microsoft product CPEs")
 *   ```
 */
func NewCPESet(name string, description string) *CPESet {
	return &CPESet{
		Items:       make([]*CPE, 0),
		Name:        name,
		Description: description,
	}
}

/**
 * Add 向集合中添加CPE
 *
 * 如果集合中已经存在相同的CPE（基于Cpe23字段比较），则不会重复添加。
 *
 * @param cpe *CPE 要添加的CPE对象
 *
 * 示例:
 *   ```go
 *   // 创建一个CPE并添加到集合
 *   windowsCPE := &cpe.CPE{
 *       Part:        *cpe.PartOperationSystem,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *   }
 *   microsoftSet.Add(windowsCPE)
 *   ```
 */
func (s *CPESet) Add(cpe *CPE) {
	// 检查是否已存在相同的CPE
	for _, item := range s.Items {
		if item.Cpe23 == cpe.Cpe23 {
			return // 已存在，不添加
		}
	}

	s.Items = append(s.Items, cpe)
}

/**
 * Remove 从集合中移除CPE
 *
 * @param cpe *CPE 要移除的CPE对象
 * @return bool 如果找到并移除了CPE则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   // 移除指定的CPE
 *   removed := microsoftSet.Remove(windowsCPE)
 *   if removed {
 *       fmt.Println("CPE已从集合中移除")
 *   } else {
 *       fmt.Println("未在集合中找到该CPE")
 *   }
 *   ```
 */
func (s *CPESet) Remove(cpe *CPE) bool {
	for i, item := range s.Items {
		if item.Cpe23 == cpe.Cpe23 {
			// 移除找到的CPE
			s.Items = append(s.Items[:i], s.Items[i+1:]...)
			return true
		}
	}

	return false // 未找到CPE
}

/**
 * Contains 检查集合是否包含指定CPE
 *
 * @param cpe *CPE 要检查的CPE对象
 * @return bool 如果集合包含该CPE则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   // 检查集合是否包含特定CPE
 *   if microsoftSet.Contains(windowsCPE) {
 *       fmt.Println("集合包含Windows CPE")
 *   }
 *   ```
 */
func (s *CPESet) Contains(cpe *CPE) bool {
	for _, item := range s.Items {
		if item.Cpe23 == cpe.Cpe23 {
			return true
		}
	}

	return false
}

/**
 * Size 返回集合中CPE的数量
 *
 * @return int 集合中CPE的数量
 */
func (s *CPESet) Size() int {
	return len(s.Items)
}

/**
 * Clear 清空集合中的所有CPE
 *
 * 示例:
 *   ```go
 *   // 清空集合
 *   microsoftSet.Clear()
 *   fmt.Printf("集合大小: %d\n", microsoftSet.Size()) // 输出: 集合大小: 0
 *   ```
 */
func (s *CPESet) Clear() {
	s.Items = make([]*CPE, 0)
}

/**
 * Union 计算两个集合的并集（包含在任一集合中的所有CPE）
 *
 * @param other *CPESet 另一个CPE集合
 * @return *CPESet 包含两个集合所有唯一CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 计算两个集合的并集
 *   microsoftSet := cpe.NewCPESet("Microsoft", "Microsoft CPEs")
 *   appleSet := cpe.NewCPESet("Apple", "Apple CPEs")
 *
 *   // 添加CPE到各自集合...
 *
 *   // 计算并集
 *   allVendorsSet := microsoftSet.Union(appleSet)
 *   fmt.Printf("并集大小: %d\n", allVendorsSet.Size())
 *   ```
 */
func (s *CPESet) Union(other *CPESet) *CPESet {
	result := NewCPESet(
		fmt.Sprintf("Union of %s and %s", s.Name, other.Name),
		fmt.Sprintf("Union of sets %s and %s", s.Name, other.Name),
	)

	// 添加第一个集合的所有元素
	for _, cpe := range s.Items {
		result.Add(cpe)
	}

	// 添加第二个集合的所有元素
	for _, cpe := range other.Items {
		result.Add(cpe)
	}

	return result
}

/**
 * Intersection 计算两个集合的交集（同时存在于两个集合中的CPE）
 *
 * @param other *CPESet 另一个CPE集合
 * @return *CPESet 仅包含同时存在于两个集合中的CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 计算两个集合的交集
 *   windowsSet := cpe.NewCPESet("Windows", "Windows CPEs")
 *   vulnerableSet := cpe.NewCPESet("Vulnerable", "Vulnerable CPEs")
 *
 *   // 添加CPE到各自集合...
 *
 *   // 计算交集，找出有漏洞的Windows系统
 *   vulnerableWindowsSet := windowsSet.Intersection(vulnerableSet)
 *   ```
 */
func (s *CPESet) Intersection(other *CPESet) *CPESet {
	result := NewCPESet(
		fmt.Sprintf("Intersection of %s and %s", s.Name, other.Name),
		fmt.Sprintf("Intersection of sets %s and %s", s.Name, other.Name),
	)

	// 添加同时在两个集合中的元素
	for _, cpe := range s.Items {
		if other.Contains(cpe) {
			result.Add(cpe)
		}
	}

	return result
}

/**
 * Difference 计算两个集合的差集（在第一个集合中但不在第二个集合中的CPE）
 *
 * @param other *CPESet 另一个CPE集合
 * @return *CPESet 包含在s中但不在other中的CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 计算两个集合的差集
 *   allWindowsSet := cpe.NewCPESet("All Windows", "All Windows versions")
 *   outdatedSet := cpe.NewCPESet("Outdated", "Outdated Windows versions")
 *
 *   // 添加CPE到各自集合...
 *
 *   // 计算差集，找出所有非过时的Windows版本
 *   supportedWindowsSet := allWindowsSet.Difference(outdatedSet)
 *   ```
 */
func (s *CPESet) Difference(other *CPESet) *CPESet {
	result := NewCPESet(
		fmt.Sprintf("Difference of %s and %s", s.Name, other.Name),
		fmt.Sprintf("Elements in %s but not in %s", s.Name, other.Name),
	)

	// 添加在s中但不在other中的元素
	for _, cpe := range s.Items {
		if !other.Contains(cpe) {
			result.Add(cpe)
		}
	}

	return result
}

/**
 * Filter 根据条件过滤集合，使用基本匹配选项
 *
 * @param criteria *CPE 用作过滤条件的CPE对象
 * @param options *MatchOptions 匹配选项，如果为nil则使用默认选项
 * @return *CPESet 包含所有匹配条件的CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 创建过滤条件
 *   criteria := &cpe.CPE{
 *       Vendor: cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *   }
 *
 *   // 使用自定义匹配选项过滤集合
 *   options := cpe.DefaultMatchOptions()
 *   options.IgnoreCase = true
 *
 *   // 过滤集合
 *   windowsSet := allProductsSet.Filter(criteria, options)
 *   ```
 */
func (s *CPESet) Filter(criteria *CPE, options *MatchOptions) *CPESet {
	if options == nil {
		options = DefaultMatchOptions()
	}

	result := NewCPESet(
		fmt.Sprintf("Filtered %s", s.Name),
		fmt.Sprintf("Filtered subset of %s", s.Name),
	)

	// 筛选匹配条件的CPE
	for _, cpe := range s.Items {
		if matchCPE(cpe, criteria, options) {
			result.Add(cpe)
		}
	}

	return result
}

/**
 * AdvancedFilter 使用高级匹配选项过滤集合
 *
 * 高级过滤支持更复杂的匹配方式，如正则表达式、相似度匹配等。
 *
 * @param criteria *CPE 用作过滤条件的CPE对象
 * @param options *AdvancedMatchOptions 高级匹配选项，如果为nil则使用默认选项
 * @return *CPESet 包含所有匹配条件的CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 创建高级过滤条件
 *   criteria := &cpe.CPE{
 *       ProductName: cpe.Product("windows"),
 *       Version: cpe.Version("10"),
 *   }
 *
 *   // 使用高级匹配选项
 *   options := cpe.NewAdvancedMatchOptions()
 *   options.MatchMode = "regex"  // 使用正则表达式匹配
 *
 *   // 过滤集合
 *   windows10Set := allProductsSet.AdvancedFilter(criteria, options)
 *   ```
 */
func (s *CPESet) AdvancedFilter(criteria *CPE, options *AdvancedMatchOptions) *CPESet {
	if options == nil {
		options = NewAdvancedMatchOptions()
	}

	result := NewCPESet(
		fmt.Sprintf("Advanced filtered %s", s.Name),
		fmt.Sprintf("Advanced filtered subset of %s", s.Name),
	)

	// 筛选匹配条件的CPE
	for _, cpe := range s.Items {
		if AdvancedMatchCPE(criteria, cpe, options) {
			result.Add(cpe)
		}
	}

	return result
}

/**
 * Sort 对集合中的CPE进行排序
 *
 * @param sortBy string 排序字段，可以是"part"、"vendor"、"product"、"version"或其他属性
 * @param ascending bool 是否按升序排序，false表示降序
 *
 * 示例:
 *   ```go
 *   // 按产品名称升序排序
 *   microsoftSet.Sort("product", true)
 *
 *   // 按版本号降序排序（最新版本在前）
 *   microsoftSet.Sort("version", false)
 *   ```
 */
func (s *CPESet) Sort(sortBy string, ascending bool) {
	sorter := &cpeSorter{
		cpes:      s.Items,
		sortBy:    sortBy,
		ascending: ascending,
	}

	sort.Sort(sorter)
}

/**
 * Equals 检查两个集合是否完全相等
 *
 * 两个集合相等意味着它们包含完全相同的CPE集合，不要求顺序相同。
 *
 * @param other *CPESet 要比较的另一个集合
 * @return bool 如果两个集合包含相同的CPE则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   // 检查两个集合是否相等
 *   if set1.Equals(set2) {
 *       fmt.Println("两个集合包含相同的CPE")
 *   }
 *   ```
 */
func (s *CPESet) Equals(other *CPESet) bool {
	if s.Size() != other.Size() {
		return false
	}

	for _, cpe := range s.Items {
		if !other.Contains(cpe) {
			return false
		}
	}

	return true
}

/**
 * IsSubsetOf 检查当前集合是否是另一个集合的子集
 *
 * 如果当前集合中的所有CPE都包含在other集合中，则当前集合是other的子集。
 *
 * @param other *CPESet 要检查的超集
 * @return bool 如果当前集合是other的子集则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   // 检查windows10Set是否是windowsSet的子集
 *   if windows10Set.IsSubsetOf(windowsSet) {
 *       fmt.Println("windows10Set是windowsSet的子集")
 *   }
 *   ```
 */
func (s *CPESet) IsSubsetOf(other *CPESet) bool {
	for _, cpe := range s.Items {
		if !other.Contains(cpe) {
			return false
		}
	}

	return true
}

/**
 * IsSupersetOf 检查当前集合是否是另一个集合的超集
 *
 * 如果other集合中的所有CPE都包含在当前集合中，则当前集合是other的超集。
 *
 * @param other *CPESet 要检查的子集
 * @return bool 如果当前集合是other的超集则返回true，否则返回false
 *
 * 示例:
 *   ```go
 *   // 检查windowsSet是否是windows10Set的超集
 *   if windowsSet.IsSupersetOf(windows10Set) {
 *       fmt.Println("windowsSet是windows10Set的超集")
 *   }
 *   ```
 */
func (s *CPESet) IsSupersetOf(other *CPESet) bool {
	return other.IsSubsetOf(s)
}

/**
 * ToString 返回集合的字符串表示
 *
 * 返回的字符串包含集合的名称、描述、大小以及所有CPE的列表。
 *
 * @return string 集合的字符串表示
 *
 * 示例:
 *   ```go
 *   // 获取并打印集合的字符串表示
 *   fmt.Println(microsoftSet.ToString())
 *   ```
 */
func (s *CPESet) ToString() string {
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("CPE Set: %s\n", s.Name))
	builder.WriteString(fmt.Sprintf("Description: %s\n", s.Description))
	builder.WriteString(fmt.Sprintf("Size: %d\n", s.Size()))
	builder.WriteString("Items:\n")

	for i, cpe := range s.Items {
		builder.WriteString(fmt.Sprintf("%d. %s\n", i+1, cpe.Cpe23))
	}

	return builder.String()
}

/**
 * FromArray 从CPE数组创建集合
 *
 * @param cpes []*CPE CPE对象数组
 * @param name string 新集合的名称
 * @param description string 新集合的描述
 * @return *CPESet 包含提供的所有CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 从CPE数组创建集合
 *   cpes := []*cpe.CPE{windows10CPE, windows11CPE, office365CPE}
 *   microsoftSet := cpe.FromArray(cpes, "Microsoft Products", "Microsoft Windows and Office")
 *   ```
 */
func FromArray(cpes []*CPE, name string, description string) *CPESet {
	set := NewCPESet(name, description)

	for _, cpe := range cpes {
		set.Add(cpe)
	}

	return set
}

/**
 * FindRelated 查找与给定CPE相关的所有CPE
 *
 * 此方法使用相似度匹配查找可能相关的CPE，适用于相似产品查找、漏洞关联分析等场景。
 *
 * @param cpe *CPE 用于查找相关CPE的参考CPE对象
 * @param options *AdvancedMatchOptions 高级匹配选项，如果为nil则使用默认选项
 * @return *CPESet 包含所有相关CPE的新集合
 *
 * 示例:
 *   ```go
 *   // 查找与Windows 10相关的所有CPE
 *   windows10CPE := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *   }
 *
 *   // 找出所有相关CPE
 *   relatedCPEs := allProductsSet.FindRelated(windows10CPE, nil)
 *   fmt.Printf("找到%d个相关CPE\n", relatedCPEs.Size())
 *   ```
 */
func (s *CPESet) FindRelated(cpe *CPE, options *AdvancedMatchOptions) *CPESet {
	if options == nil {
		options = NewAdvancedMatchOptions()
	}

	// 默认使用宽松匹配模式
	options.MatchMode = "distance"
	options.ScoreThreshold = 0.6 // 降低匹配阈值，更宽松

	return s.AdvancedFilter(cpe, options)
}

/**
 * cpeSorter 用于CPE排序的辅助结构
 *
 * 实现了sort.Interface接口，用于对CPE集合进行排序。
 */
type cpeSorter struct {
	// cpes 要排序的CPE对象数组
	cpes []*CPE

	// sortBy 排序字段名称
	sortBy string

	// ascending 是否升序排序
	ascending bool
}

/**
 * Len 返回要排序的CPE数量
 *
 * 实现sort.Interface接口的方法。
 *
 * @return int CPE数组的长度
 */
func (s *cpeSorter) Len() int {
	return len(s.cpes)
}

/**
 * Swap 交换两个CPE的位置
 *
 * 实现sort.Interface接口的方法。
 *
 * @param i int 第一个CPE的索引
 * @param j int 第二个CPE的索引
 */
func (s *cpeSorter) Swap(i, j int) {
	s.cpes[i], s.cpes[j] = s.cpes[j], s.cpes[i]
}

/**
 * Less 比较两个CPE的大小关系
 *
 * 实现sort.Interface接口的方法。根据sortBy字段和ascending标志确定排序顺序。
 *
 * @param i int 第一个CPE的索引
 * @param j int 第二个CPE的索引
 * @return bool 如果第一个CPE应排在第二个CPE之前则返回true，否则返回false
 */
func (s *cpeSorter) Less(i, j int) bool {
	var result bool

	switch s.sortBy {
	case "part":
		result = s.cpes[i].Part.ShortName < s.cpes[j].Part.ShortName
	case "vendor":
		result = string(s.cpes[i].Vendor) < string(s.cpes[j].Vendor)
	case "product":
		result = string(s.cpes[i].ProductName) < string(s.cpes[j].ProductName)
	case "version":
		// 使用版本比较函数
		v1 := versions.NewVersion(string(s.cpes[i].Version))
		v2 := versions.NewVersion(string(s.cpes[j].Version))
		result = v1.CompareTo(v2) < 0
	default:
		// 默认按照Cpe23排序
		result = s.cpes[i].Cpe23 < s.cpes[j].Cpe23
	}

	if !s.ascending {
		result = !result
	}

	return result
}
