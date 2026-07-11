package cpeskills

import (
	"fmt"
	"strings"
)

// Component 接口定义CPE组件类型的通用行为
type Component interface {
	// String 返回组件的字符串表示
	String() string
	// IsANY 判断组件是否为ANY值
	IsANY() bool
	// IsNA 判断组件是否为NA值
	IsNA() bool
	// IsSet 判断组件是否设置了有效值（非ANY/NA/空）
	IsSet() bool
	// Normalize 标准化组件值
	Normalize() string
}

// ParsePart 解析Part字符串，返回对应的Part对象
func ParsePart(s string) (Part, error) {
	switch strings.ToLower(s) {
	case PartApplicationShort:
		return *PartApplication, nil
	case PartHardwareShort:
		return *PartHardware, nil
	case PartOSShort:
		return *PartOperationSystem, nil
	case ValueANY:
		return Part{ShortName: ValueANY, LongName: "ANY"}, nil
	default:
		return Part{}, fmt.Errorf("invalid part value: %s", s)
	}
}

// String 返回Vendor的字符串表示
func (v Vendor) String() string { return string(v) }

// IsANY 判断Vendor是否为ANY值
func (v Vendor) IsANY() bool { return string(v) == ValueANY }

// IsNA 判断Vendor是否为NA值
func (v Vendor) IsNA() bool { return string(v) == ValueNA }

// IsSet 判断Vendor是否设置了有效值
func (v Vendor) IsSet() bool { s := string(v); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Vendor值
func (v Vendor) Normalize() string { return NormalizeComponent(string(v)) }

// String 返回Product的字符串表示
func (p Product) String() string { return string(p) }

// IsANY 判断Product是否为ANY值
func (p Product) IsANY() bool { return string(p) == ValueANY }

// IsNA 判断Product是否为NA值
func (p Product) IsNA() bool { return string(p) == ValueNA }

// IsSet 判断Product是否设置了有效值
func (p Product) IsSet() bool { s := string(p); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Product值
func (p Product) Normalize() string { return NormalizeComponent(string(p)) }

// String 返回Version的字符串表示
func (v Version) String() string { return string(v) }

// IsANY 判断Version是否为ANY值
func (v Version) IsANY() bool { return string(v) == ValueANY }

// IsNA 判断Version是否为NA值
func (v Version) IsNA() bool { return string(v) == ValueNA }

// IsSet 判断Version是否设置了有效值
func (v Version) IsSet() bool { s := string(v); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Version值
func (v Version) Normalize() string { return NormalizeComponent(string(v)) }

// String 返回Edition的字符串表示
func (e Edition) String() string { return string(e) }

// IsANY 判断Edition是否为ANY值
func (e Edition) IsANY() bool { return string(e) == ValueANY }

// IsNA 判断Edition是否为NA值
func (e Edition) IsNA() bool { return string(e) == ValueNA }

// IsSet 判断Edition是否设置了有效值
func (e Edition) IsSet() bool { s := string(e); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Edition值
func (e Edition) Normalize() string { return NormalizeComponent(string(e)) }

// String 返回Language的字符串表示
func (l Language) String() string { return string(l) }

// IsANY 判断Language是否为ANY值
func (l Language) IsANY() bool { return string(l) == ValueANY }

// IsNA 判断Language是否为NA值
func (l Language) IsNA() bool { return string(l) == ValueNA }

// IsSet 判断Language是否设置了有效值
func (l Language) IsSet() bool { s := string(l); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Language值
func (l Language) Normalize() string { return NormalizeComponent(string(l)) }

// String 返回Update的字符串表示
func (u Update) String() string { return string(u) }

// IsANY 判断Update是否为ANY值
func (u Update) IsANY() bool { return string(u) == ValueANY }

// IsNA 判断Update是否为NA值
func (u Update) IsNA() bool { return string(u) == ValueNA }

// IsSet 判断Update是否设置了有效值
func (u Update) IsSet() bool { s := string(u); return s != "" && s != ValueANY && s != ValueNA }

// Normalize 标准化Update值
func (u Update) Normalize() string { return NormalizeComponent(string(u)) }

// Part类型的方法

// IsANY 判断Part是否为ANY值
func (p Part) IsANY() bool { return p.ShortName == ValueANY }

// IsNA 判断Part是否为NA值
func (p Part) IsNA() bool { return p.ShortName == ValueNA }

// IsSet 判断Part是否设置了有效值
func (p Part) IsSet() bool {
	return p.ShortName != "" && p.ShortName != ValueANY && p.ShortName != ValueNA
}

// Normalize 标准化Part值
func (p Part) Normalize() string { return strings.ToLower(p.ShortName) }
