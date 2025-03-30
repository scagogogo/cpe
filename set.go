package cpe

import (
	"fmt"
	"sort"
	"strings"
)

// CPESet 表示CPE集合
type CPESet struct {
	// CPE列表
	Items []*CPE

	// 集合名称
	Name string

	// 集合描述
	Description string
}

// NewCPESet 创建新的CPE集合
func NewCPESet(name string, description string) *CPESet {
	return &CPESet{
		Items:       make([]*CPE, 0),
		Name:        name,
		Description: description,
	}
}

// Add 向集合中添加CPE
func (s *CPESet) Add(cpe *CPE) {
	// 检查是否已存在相同的CPE
	for _, item := range s.Items {
		if item.Cpe23 == cpe.Cpe23 {
			return // 已存在，不添加
		}
	}

	s.Items = append(s.Items, cpe)
}

// Remove 从集合中移除CPE
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

// Contains 检查集合是否包含指定CPE
func (s *CPESet) Contains(cpe *CPE) bool {
	for _, item := range s.Items {
		if item.Cpe23 == cpe.Cpe23 {
			return true
		}
	}

	return false
}

// Size 返回集合大小
func (s *CPESet) Size() int {
	return len(s.Items)
}

// Clear 清空集合
func (s *CPESet) Clear() {
	s.Items = make([]*CPE, 0)
}

// Union 计算两个集合的并集
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

// Intersection 计算两个集合的交集
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

// Difference 计算两个集合的差集 (s - other)
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

// Filter 根据条件过滤集合
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

// AdvancedFilter 使用高级匹配选项过滤集合
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

// Sort 对集合进行排序
func (s *CPESet) Sort(sortBy string, ascending bool) {
	sorter := &cpeSorter{
		cpes:      s.Items,
		sortBy:    sortBy,
		ascending: ascending,
	}

	sort.Sort(sorter)
}

// Equals 检查两个集合是否相等
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

// IsSubsetOf 检查当前集合是否是另一个集合的子集
func (s *CPESet) IsSubsetOf(other *CPESet) bool {
	for _, cpe := range s.Items {
		if !other.Contains(cpe) {
			return false
		}
	}

	return true
}

// IsSupersetOf 检查当前集合是否是另一个集合的超集
func (s *CPESet) IsSupersetOf(other *CPESet) bool {
	return other.IsSubsetOf(s)
}

// ToString 返回集合的字符串表示
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

// FromArray 从CPE数组创建集合
func FromArray(cpes []*CPE, name string, description string) *CPESet {
	set := NewCPESet(name, description)

	for _, cpe := range cpes {
		set.Add(cpe)
	}

	return set
}

// FindRelated 查找与给定CPE相关的所有CPE
func (s *CPESet) FindRelated(cpe *CPE, options *AdvancedMatchOptions) *CPESet {
	if options == nil {
		options = NewAdvancedMatchOptions()
	}

	// 默认使用宽松匹配模式
	options.MatchMode = "distance"
	options.ScoreThreshold = 0.6 // 降低匹配阈值，更宽松

	return s.AdvancedFilter(cpe, options)
}

// cpeSorter 辅助类型，用于排序CPE
type cpeSorter struct {
	cpes      []*CPE
	sortBy    string
	ascending bool
}

// Len 实现sort.Interface
func (s *cpeSorter) Len() int {
	return len(s.cpes)
}

// Swap 实现sort.Interface
func (s *cpeSorter) Swap(i, j int) {
	s.cpes[i], s.cpes[j] = s.cpes[j], s.cpes[i]
}

// Less 实现sort.Interface
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
		compareResult := compareVersionsSimple(string(s.cpes[i].Version), string(s.cpes[j].Version))
		result = compareResult < 0
	default:
		// 默认按照Cpe23排序
		result = s.cpes[i].Cpe23 < s.cpes[j].Cpe23
	}

	if !s.ascending {
		result = !result
	}

	return result
}
