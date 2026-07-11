package cpeskills

import (
	"fmt"
	"net/url"
	"strings"
)

// PackageURL 表示一个 Package URL (PURL)，符合 https://github.com/package-url/purl-spec 规范
//
// PURL 是一种标准化的包标识符，用于在 SCA 工具、SBOM 和漏洞数据库中
// 唯一标识软件包。格式为: scheme:type/namespace/name@version?qualifiers#subpath
//
// 示例:
//
//	pkg:npm/express@4.17.1
//	pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
//	pkg:pypi/django@4.2.0
//	pkg:golang/github.com/gin-gonic/gin@1.9.0
type PackageURL struct {
	// Type 包类型/生态系统 (npm, maven, pypi, golang, nuget, etc.)
	Type string

	// Namespace 命名空间 (@scope for npm, groupId for Maven)
	Namespace string

	// Name 包名称
	Name string

	// Version 包版本
	Version string

	// Qualifiers 限定符，键值对形式
	// 如: {"arch": "amd64", "os": "linux"}
	Qualifiers map[string]string

	// Subpath 子路径
	Subpath string
}

// ParsePURL 解析 PURL 字符串为 PackageURL 结构体
//
// 支持的格式:
//
//	pkg:type/name@version
//	pkg:type/namespace/name@version
//	pkg:type/namespace/name@version?key=value&key2=value2
//	pkg:type/namespace/name@version?key=value#subpath
func ParsePURL(raw string) (*PackageURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty purl string")
	}

	// 检查 scheme
	if !strings.HasPrefix(raw, "pkg:") {
		return nil, fmt.Errorf("invalid purl: must start with 'pkg:'")
	}

	// 移除 scheme
	rest := raw[4:]

	// 提取 subpath
	var subpath string
	if idx := strings.Index(rest, "#"); idx >= 0 {
		subpath = rest[idx+1:]
		rest = rest[:idx]
	}

	// 提取 qualifiers
	var qualifiers map[string]string
	if idx := strings.Index(rest, "?"); idx >= 0 {
		qStr := rest[idx+1:]
		rest = rest[:idx]
		var err error
		qualifiers, err = parsePURLQualifiers(qStr)
		if err != nil {
			return nil, fmt.Errorf("invalid purl qualifiers: %w", err)
		}
	}

	// 提取 version
	var version string
	if idx := strings.LastIndex(rest, "@"); idx >= 0 {
		version = rest[idx+1:]
		rest = rest[:idx]
	}

	// 解析 type/namespace/name
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid purl: missing type and name")
	}

	purlType := parts[0]
	if purlType == "" {
		return nil, fmt.Errorf("invalid purl: type cannot be empty")
	}

	var namespace, name string
	switch len(parts) {
	case 2:
		name = parts[1]
	case 3:
		namespace = parts[1]
		name = parts[2]
	}

	if name == "" {
		return nil, fmt.Errorf("invalid purl: name cannot be empty")
	}

	// URL-decode 各部分
	decodedType, err := url.PathUnescape(purlType)
	if err != nil {
		return nil, fmt.Errorf("invalid purl type encoding: %w", err)
	}
	decodedNamespace, err := url.PathUnescape(namespace)
	if err != nil {
		return nil, fmt.Errorf("invalid purl namespace encoding: %w", err)
	}
	decodedName, err := url.PathUnescape(name)
	if err != nil {
		return nil, fmt.Errorf("invalid purl name encoding: %w", err)
	}
	decodedVersion, err := url.PathUnescape(version)
	if err != nil {
		return nil, fmt.Errorf("invalid purl version encoding: %w", err)
	}

	return &PackageURL{
		Type:       decodedType,
		Namespace:  decodedNamespace,
		Name:       decodedName,
		Version:    decodedVersion,
		Qualifiers: qualifiers,
		Subpath:    subpath,
	}, nil
}

// String 将 PackageURL 格式化为标准 PURL 字符串
func (p *PackageURL) String() string {
	if p == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("pkg:")
	sb.WriteString(url.PathEscape(p.Type))
	sb.WriteString("/")
	if p.Namespace != "" {
		sb.WriteString(url.PathEscape(p.Namespace))
		sb.WriteString("/")
	}
	sb.WriteString(url.PathEscape(p.Name))

	if p.Version != "" {
		sb.WriteString("@")
		sb.WriteString(url.PathEscape(p.Version))
	}

	if len(p.Qualifiers) > 0 {
		sb.WriteString("?")
		first := true
		// 按字母顺序排序以保证输出稳定
		keys := sortedQualifierKeys(p.Qualifiers)
		for _, k := range keys {
			if !first {
				sb.WriteString("&")
			}
			sb.WriteString(url.QueryEscape(k))
			sb.WriteString("=")
			sb.WriteString(url.QueryEscape(p.Qualifiers[k]))
			first = false
		}
	}

	if p.Subpath != "" {
		sb.WriteString("#")
		sb.WriteString(p.Subpath)
	}

	return sb.String()
}

// IsValid 检查 PURL 是否有效
func (p *PackageURL) IsValid() bool {
	if p == nil {
		return false
	}
	return p.Type != "" && p.Name != ""
}

// Ecosystem 返回 PURL 对应的生态系统
func (p *PackageURL) Ecosystem() Ecosystem {
	if p == nil {
		return EcosystemGeneric
	}
	return EcosystemFromPURLType(p.Type)
}

// FullName 返回包含命名空间的完整包名
// 例如: "org.apache.logging.log4j/log4j-core" 或 "express"
func (p *PackageURL) FullName() string {
	if p == nil {
		return ""
	}
	if p.Namespace != "" {
		return p.Namespace + "/" + p.Name
	}
	return p.Name
}

// Copy 创建 PURL 的深拷贝
func (p *PackageURL) Copy() *PackageURL {
	if p == nil {
		return nil
	}
	qualifiers := make(map[string]string, len(p.Qualifiers))
	for k, v := range p.Qualifiers {
		qualifiers[k] = v
	}
	return &PackageURL{
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: qualifiers,
		Subpath:    p.Subpath,
	}
}

// WithoutVersion 返回不带版本号的 PURL 副本
func (p *PackageURL) WithoutVersion() *PackageURL {
	cp := p.Copy()
	if cp != nil {
		cp.Version = ""
	}
	return cp
}

// WithVersion 返回带指定版本号的 PURL 副本
func (p *PackageURL) WithVersion(version string) *PackageURL {
	cp := p.Copy()
	if cp != nil {
		cp.Version = version
	}
	return cp
}

// Equals 比较两个 PURL 是否相等（忽略 qualifiers 顺序）
func (p *PackageURL) Equals(other *PackageURL) bool {
	if p == nil && other == nil {
		return true
	}
	if p == nil || other == nil {
		return false
	}
	if p.Type != other.Type || p.Namespace != other.Namespace ||
		p.Name != other.Name || p.Version != other.Version ||
		p.Subpath != other.Subpath {
		return false
	}
	if len(p.Qualifiers) != len(other.Qualifiers) {
		return false
	}
	for k, v := range p.Qualifiers {
		if ov, ok := other.Qualifiers[k]; !ok || ov != v {
			return false
		}
	}
	return true
}

// NewPURL 创建一个新的 PackageURL
func NewPURL(purlType, namespace, name, version string) *PackageURL {
	return &PackageURL{
		Type:       purlType,
		Namespace:  namespace,
		Name:       name,
		Version:    version,
		Qualifiers: make(map[string]string),
	}
}

// NewPURLWithEcosystem 使用生态系统创建 PURL
func NewPURLWithEcosystem(ecosystem Ecosystem, namespace, name, version string) (*PackageURL, error) {
	info, err := GetEcosystemInfo(ecosystem)
	if err != nil {
		return nil, err
	}
	return NewPURL(info.PURLType, namespace, name, version), nil
}

// parsePURLQualifiers 解析 PURL 限定符字符串
func parsePURLQualifiers(s string) (map[string]string, error) {
	result := make(map[string]string)
	if s == "" {
		return result, nil
	}

	pairs := strings.Split(s, "&")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid qualifier pair: %s", pair)
		}
		key, err := url.QueryUnescape(kv[0])
		if err != nil {
			return nil, fmt.Errorf("invalid qualifier key encoding: %w", err)
		}
		value, err := url.QueryUnescape(kv[1])
		if err != nil {
			return nil, fmt.Errorf("invalid qualifier value encoding: %w", err)
		}
		result[key] = value
	}

	return result, nil
}

// sortedQualifierKeys 返回按字母顺序排序的限定符键列表
func sortedQualifierKeys(qualifiers map[string]string) []string {
	keys := make([]string, 0, len(qualifiers))
	for k := range qualifiers {
		keys = append(keys, k)
	}
	// 简单插入排序，避免导入 sort 包
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && keys[j] < keys[j-1] {
			keys[j], keys[j-1] = keys[j-1], keys[j]
			j--
		}
	}
	return keys
}
