package cpeskills

import (
	"fmt"
	"strings"

	"github.com/scagogogo/versions"
)

// CompareVersions 比较两个版本字符串
// 返回: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func CompareVersions(v1, v2 string) int {
	ver1 := versions.NewVersion(v1)
	ver2 := versions.NewVersion(v2)
	return ver1.CompareTo(ver2)
}

// IsVersionInRange 检查版本是否在指定范围内
// 包含边界值（闭区间）
func IsVersionInRange(version, minVersion, maxVersion string) bool {
	if minVersion != "" {
		if CompareVersions(version, minVersion) < 0 {
			return false
		}
	}
	if maxVersion != "" {
		if CompareVersions(version, maxVersion) > 0 {
			return false
		}
	}
	return true
}

// IsSubVersion 检查subVersion是否是parentVersion的子版本
// 例如 1.0.1 是 1.0 的子版本
func IsSubVersion(parentVersion, subVersion string) bool {
	parent := versions.NewVersion(parentVersion)
	child := versions.NewVersion(subVersion)

	parentNums := parent.VersionNumbers
	childNums := child.VersionNumbers

	// 子版本的数字部分应该至少和父版本一样长
	if len(childNums) < len(parentNums) {
		return false
	}

	// 比较公共前缀部分的每个版本号段
	for i := 0; i < len(parentNums); i++ {
		if parentNums[i] != childNums[i] {
			return false
		}
	}

	// 如果子版本的数字部分更长，则是子版本
	if len(childNums) > len(parentNums) {
		return true
	}

	// 长度相同时，检查后缀是否兼容
	return parent.Suffix == child.Suffix
}

// VersionRange 表示版本范围
type VersionRange struct {
	MinVersion string // 最小版本（包含）
	MaxVersion string // 最大版本（包含）
}

// ParseVersionRange 解析版本范围字符串
// 支持格式:
//   - "1.0" -> 精确版本
//   - "1.0-2.0" -> 范围（从1.0到2.0）
//   - "1.0+" -> 1.0及以上
//   - "-2.0" -> 2.0及以下
func ParseVersionRange(s string) (*VersionRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty version range")
	}

	// 处理 "x+" 格式（x及以上）
	if strings.HasSuffix(s, "+") {
		return &VersionRange{
			MinVersion: strings.TrimSuffix(s, "+"),
			MaxVersion: "",
		}, nil
	}

	// 处理 "x-y" 格式（范围）
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		return &VersionRange{
			MinVersion: strings.TrimSpace(parts[0]),
			MaxVersion: strings.TrimSpace(parts[1]),
		}, nil
	}

	// 精确版本
	return &VersionRange{
		MinVersion: s,
		MaxVersion: s,
	}, nil
}

// Contains 检查版本是否在范围内
func (vr *VersionRange) Contains(version string) bool {
	return IsVersionInRange(version, vr.MinVersion, vr.MaxVersion)
}