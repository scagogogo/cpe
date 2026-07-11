package cpeskills

// Relation 表示两个CPE之间的匹配关系
// 按照 NISTIR 7696 CPE Name Matching 规范定义
type Relation int

const (
	// RelationDisjoint 表示两个CPE不相交，没有重叠
	RelationDisjoint Relation = iota

	// RelationSubset 表示源CPE是目标CPE的子集
	RelationSubset

	// RelationSuperset 表示源CPE是目标CPE的超集
	RelationSuperset

	// RelationEqual 表示两个CPE相等
	RelationEqual

	// RelationOverlap 表示两个CPE有重叠但不完全包含
	RelationOverlap

	// RelationUnknown 表示关系无法确定
	RelationUnknown
)

// String 返回Relation的字符串表示
func (r Relation) String() string {
	switch r {
	case RelationDisjoint:
		return "disjoint"
	case RelationSubset:
		return "subset"
	case RelationSuperset:
		return "superset"
	case RelationEqual:
		return "equal"
	case RelationOverlap:
		return "overlap"
	case RelationUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// CompareAttributes 比较两个WFN属性值之间的关系
// 按照 NISTIR 7696 规范中的属性比较规则
// 返回: 1 = superset, 0 = equal, -1 = subset, -2 = disjoint
func CompareAttributes(source, target string) int {
	// 将空值视为ANY
	if source == "" {
		source = ValueANY
	}
	if target == "" {
		target = ValueANY
	}

	// ANY匹配任何值
	if source == ValueANY && target == ValueANY {
		return 0
	}
	if source == ValueANY {
		return 1 // source是ANY，所以source是target的超集
	}
	if target == ValueANY {
		return -1 // target是ANY，所以source是target的子集
	}

	// NA的情况
	if source == ValueNA && target == ValueNA {
		return 0
	}
	if source == ValueNA {
		return -2 // NA和任何非NA值不相交
	}
	if target == ValueNA {
		return -2
	}

	// 检查通配符匹配
	if hasWildcardPattern(source) || hasWildcardPattern(target) {
		if wildcardMatch(source, target) {
			if hasWildcardPattern(source) && !hasWildcardPattern(target) {
				return 1 // source有通配符，是超集
			}
			if !hasWildcardPattern(source) && hasWildcardPattern(target) {
				return -1 // target有通配符，source是子集
			}
			return 0 // 都有通配符且匹配
		}
		return -2 // 通配符不匹配
	}

	// 精确匹配
	if source == target {
		return 0
	}

	return -2 // 不相等也不相交
}

// CompareWFNs 比较两个WFN的各属性，返回每个属性的比较结果
func CompareWFNs(source, target *WFN) map[string]int {
	if source == nil {
		source = NewWFN()
	}
	if target == nil {
		target = NewWFN()
	}

	result := make(map[string]int, len(allAttributes))
	for _, attr := range allAttributes {
		result[attr] = CompareAttributes(source.Get(attr), target.Get(attr))
	}

	return result
}

// CompareWFNRelation 根据属性比较结果确定整体关系
func CompareWFNRelation(comparisons map[string]int) Relation {
	hasSuperset := false
	hasSubset := false
	hasDisjoint := false

	for _, cmp := range comparisons {
		switch cmp {
		case 1:
			hasSuperset = true
		case -1:
			hasSubset = true
		case -2:
			hasDisjoint = true
		case 0:
			// equal, 不影响关系
		}
	}

	if hasDisjoint {
		return RelationDisjoint
	}

	if hasSuperset && hasSubset {
		return RelationOverlap
	}

	if hasSuperset {
		return RelationSuperset
	}

	if hasSubset {
		return RelationSubset
	}

	return RelationEqual
}

// CPEDisjoint 判断两个CPE是否不相交
func CPEDisjoint(a, b *CPE) bool {
	if a == nil || b == nil {
		return true
	}
	comparisons := CompareWFNs(FromCPE(a), FromCPE(b))
	return CompareWFNRelation(comparisons) == RelationDisjoint
}

// CPEEqual 判断两个CPE是否相等
func CPEEqual(a, b *CPE) bool {
	if a == nil || b == nil {
		return false
	}
	comparisons := CompareWFNs(FromCPE(a), FromCPE(b))
	return CompareWFNRelation(comparisons) == RelationEqual
}

// CPESubset 判断CPE a是否是CPE b的子集
func CPESubset(a, b *CPE) bool {
	if a == nil || b == nil {
		return false
	}
	comparisons := CompareWFNs(FromCPE(a), FromCPE(b))
	relation := CompareWFNRelation(comparisons)
	return relation == RelationSubset || relation == RelationEqual
}

// CPESuperset 判断CPE a是否是CPE b的超集
func CPESuperset(a, b *CPE) bool {
	if a == nil || b == nil {
		return false
	}
	comparisons := CompareWFNs(FromCPE(a), FromCPE(b))
	relation := CompareWFNRelation(comparisons)
	return relation == RelationSuperset || relation == RelationEqual
}

// hasWildcardPattern 检查字符串是否包含通配符模式
func hasWildcardPattern(value string) bool {
	return hasUnquotedWildcard(value)
}

// wildcardMatch 检查source模式是否匹配target值
// source可以包含*和?通配符
func wildcardMatch(source, target string) bool {
	// 简单的通配符匹配实现
	si := 0
	ti := 0
	starIdx := -1
	matchIdx := 0

	for ti < len(target) {
		if si < len(source) {
			sc := source[si]
			// 处理转义字符
			if sc == '\\' && si+1 < len(source) {
				sc = source[si+1]
				if ti < len(target) && target[ti] == sc {
					si += 2
					ti++
					continue
				}
				return false
			}
			if sc == '*' {
				starIdx = si
				matchIdx = ti
				si++
				continue
			}
			if sc == '?' || sc == target[ti] {
				si++
				ti++
				continue
			}
		}

		if starIdx != -1 {
			si = starIdx + 1
			matchIdx++
			ti = matchIdx
			continue
		}

		return false
	}

	// 处理source末尾的*
	for si < len(source) {
		if source[si] == '\\' && si+1 < len(source) {
			break
		}
		if source[si] == '*' {
			si++
		} else {
			break
		}
	}

	return si >= len(source)
}
