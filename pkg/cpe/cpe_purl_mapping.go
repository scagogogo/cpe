package cpeskills

import (
	"fmt"
	"strings"
)

// CPEToPURL 将 CPE 转换为 PackageURL，返回 PURL 和置信度分数
//
// 置信度范围 0.0-1.0，数值越高表示映射越确定。
// 映射规则基于常见 CPE vendor/product 命名约定与包生态系统的对应关系。
func CPEToPURL(cpe *CPE) (*PackageURL, float64, error) {
	if cpe == nil {
		return nil, 0, fmt.Errorf("cannot convert nil CPE to PURL")
	}

	vendor := strings.ToLower(string(cpe.Vendor))
	product := strings.ToLower(string(cpe.ProductName))
	version := string(cpe.Version)

	// 尝试根据 vendor 推断生态系统
	ecosystem, confidence := inferEcosystem(vendor, product)

	// 根据生态系统构建 PURL
	purl, err := buildPURLFromCPE(cpe, ecosystem, vendor, product, version)
	if err != nil {
		return nil, 0, err
	}

	// 调整置信度
	if version == "" || version == "*" {
		confidence *= 0.8 // 缺少版本降低置信度
	}

	return purl, confidence, nil
}

// PURLToCPE 将 PackageURL 转换为 CPE，返回 CPE 和置信度分数
func PURLToCPE(purl *PackageURL) (*CPE, float64, error) {
	if purl == nil {
		return nil, 0, fmt.Errorf("cannot convert nil PURL to CPE")
	}

	ecosystem := purl.Ecosystem()
	vendor, product := inferVendorProductFromPURL(purl, ecosystem)

	cpe := &CPE{
		Cpe23:       "", // 由 FormatCpe23 生成
		Part:        *PartApplication,
		Vendor:      Vendor(strings.ToLower(strings.ReplaceAll(vendor, " ", "_"))),
		ProductName: Product(strings.ToLower(strings.ReplaceAll(product, " ", "_"))),
		Version:     Version(purl.Version),
		Update:      Update(ValueANY),
		Edition:     Edition(ValueANY),
		Language:    Language(ValueANY),
	}
	cpe.Cpe23 = FormatCpe23(cpe)

	// 计算置信度
	confidence := 0.9
	if purl.Version == "" {
		confidence *= 0.7
	}
	if ecosystem == EcosystemGeneric {
		confidence *= 0.5
	}

	return cpe, confidence, nil
}

// MapCPEToPURLWithEcosystem 使用指定的生态系统将 CPE 转换为 PURL
// 相比自动推断的 CPEToPURL，此函数允许用户指定目标生态系统以获得更高置信度
func MapCPEToPURLWithEcosystem(cpe *CPE, ecosystem Ecosystem) (*PackageURL, error) {
	if cpe == nil {
		return nil, fmt.Errorf("cannot convert nil CPE to PURL")
	}

	info, err := GetEcosystemInfo(ecosystem)
	if err != nil {
		return nil, fmt.Errorf("unknown ecosystem: %w", err)
	}

	vendor := strings.ToLower(string(cpe.Vendor))
	product := strings.ToLower(string(cpe.ProductName))

	purl := NewPURL(info.PURLType, "", product, string(cpe.Version))

	// 根据生态系统设置命名空间
	switch ecosystem {
	case EcosystemMaven:
		// Maven: 使用 vendor 作为 groupId
		if vendor != "" && vendor != ValueANY {
			purl.Namespace = vendor
			purl.Name = product
		}
	case EcosystemNPM:
		// npm: 如果 vendor 有意义，作为 scope
		if vendor != "" && vendor != ValueANY {
			purl.Namespace = "@" + vendor
			purl.Name = product
		}
	case EcosystemGo:
		// Go: vendor 通常是模块路径前缀
		if vendor != "" && vendor != ValueANY {
			purl.Name = vendor + "/" + product
		}
	case EcosystemDocker:
		// Docker: vendor/product → namespace/name
		if vendor != "" && vendor != ValueANY {
			purl.Namespace = vendor
		}
	default:
		// 其他生态系统：vendor 不重要
	}

	return purl, nil
}

// BatchCPEToPURL 批量转换 CPE 为 PURL
func BatchCPEToPURL(cpes []*CPE) map[string]*PackageURL {
	result := make(map[string]*PackageURL, len(cpes))
	for _, c := range cpes {
		if c == nil {
			continue
		}
		purl, _, err := CPEToPURL(c)
		if err == nil && purl != nil {
			result[c.GetURI()] = purl
		}
	}
	return result
}

// BatchPURLToCPE 批量转换 PURL 为 CPE
func BatchPURLToCPE(purls []*PackageURL) map[string]*CPE {
	result := make(map[string]*CPE, len(purls))
	for _, p := range purls {
		cpe, _, err := PURLToCPE(p)
		if err == nil && cpe != nil {
			result[p.String()] = cpe
		}
	}
	return result
}

// inferEcosystem 根据 CPE 的 vendor 和 product 推断包生态系统
func inferEcosystem(vendor, product string) (Ecosystem, float64) {
	// 已知 vendor 映射
	vendorEcosystems := map[string]struct {
		eco        Ecosystem
		confidence float64
	}{
		"apache":           {EcosystemMaven, 0.9},
		"apache_software":  {EcosystemMaven, 0.9},
		"apache foundation": {EcosystemMaven, 0.9},
		"spring":           {EcosystemMaven, 0.95},
		"springsource":     {EcosystemMaven, 0.95},
		"pivotal":          {EcosystemMaven, 0.8},
		"eclipse":          {EcosystemMaven, 0.9},
		"jenkins":          {EcosystemMaven, 0.9},
		"maven":            {EcosystemMaven, 1.0},
		"oracle":           {EcosystemMaven, 0.7}, // Oracle 也有其他产品

		"npm":        {EcosystemNPM, 1.0},
		"npmjs":      {EcosystemNPM, 1.0},
		"node.js":    {EcosystemNPM, 0.9},
		"nodejs":     {EcosystemNPM, 0.9},
		"joyent":     {EcosystemNPM, 0.8},
		"express":    {EcosystemNPM, 0.9},
		"vue":        {EcosystemNPM, 0.95},
		"vuejs":      {EcosystemNPM, 0.95},
		"facebook":   {EcosystemNPM, 0.8},
		"react":      {EcosystemNPM, 0.95},

		"python":          {EcosystemPyPI, 0.95},
		"python.org":      {EcosystemPyPI, 0.95},
		"django":          {EcosystemPyPI, 0.95},
		"djangoproject":   {EcosystemPyPI, 0.95},
		"flask":           {EcosystemPyPI, 0.95},
		"pypa":            {EcosystemPyPI, 1.0},

		"golang":  {EcosystemGo, 1.0},
		"google":  {EcosystemGo, 0.6}, // Google 有很多产品
		"github":  {EcosystemGo, 0.7},
		"golang.org": {EcosystemGo, 1.0},

		"microsoft":   {EcosystemNuGet, 0.5}, // Microsoft 有很多产品
		"nuget":       {EcosystemNuGet, 1.0},
		".net":        {EcosystemNuGet, 0.95},
		"dotnet":      {EcosystemNuGet, 0.95},
		"asp.net":     {EcosystemNuGet, 0.95},

		"rust":        {EcosystemCargo, 0.95},
		"rust-lang":   {EcosystemCargo, 1.0},
		"crates.io":   {EcosystemCargo, 1.0},

		"rubygems":    {EcosystemRubyGems, 1.0},
		"ruby":        {EcosystemRubyGems, 0.9},
		"ruby-lang":   {EcosystemRubyGems, 0.95},

		"packagist":   {EcosystemComposer, 1.0},
		"composer":    {EcosystemComposer, 1.0},

		"docker":      {EcosystemDocker, 0.95},
		"docker.io":   {EcosystemDocker, 1.0},
		"containerd":  {EcosystemDocker, 0.9},

		"conan":       {EcosystemConan, 1.0},

		"anaconda":    {EcosystemConda, 0.95},
		"conda-forge": {EcosystemConda, 1.0},

		"elixir":      {EcosystemHex, 0.9},
		"hex.pm":      {EcosystemHex, 1.0},

		"dart":        {EcosystemPub, 0.95},
		"pub.dev":     {EcosystemPub, 1.0},
		"flutter":     {EcosystemPub, 0.95},

		"apple":       {EcosystemSwift, 0.6},
		"swift.org":   {EcosystemSwift, 1.0},

		"alpine":      {EcosystemAlpine, 0.95},
		"alpinelinux": {EcosystemAlpine, 1.0},

		"debian":      {EcosystemDebian, 0.95},
		"ubuntu":      {EcosystemDebian, 0.9},

		"redhat":      {EcosystemRPM, 0.8},
		"red_hat":     {EcosystemRPM, 0.8},
		"fedora":      {EcosystemRPM, 0.95},
		"centos":      {EcosystemRPM, 0.95},
		"rpm":         {EcosystemRPM, 0.95},
	}

	if mapping, ok := vendorEcosystems[vendor]; ok {
		return mapping.eco, mapping.confidence
	}

	// 基于 product 名称的启发式推断
	if strings.HasPrefix(product, "npm-") || strings.HasPrefix(product, "node-") {
		return EcosystemNPM, 0.6
	}
	if strings.HasPrefix(product, "python-") || strings.HasPrefix(product, "python_") {
		return EcosystemPyPI, 0.6
	}
	if strings.HasPrefix(product, "go-") || strings.Contains(product, "go-module") {
		return EcosystemGo, 0.6
	}
	if strings.Contains(product, "nuget") || strings.HasPrefix(product, "dotnet-") {
		return EcosystemNuGet, 0.6
	}

	return EcosystemGeneric, 0.3
}

// buildPURLFromCPE 根据推断的生态系统构建 PURL
func buildPURLFromCPE(cpe *CPE, ecosystem Ecosystem, vendor, product, version string) (*PackageURL, error) {
	info, err := GetEcosystemInfo(ecosystem)
	if err != nil {
		// fallback to generic
		info = EcosystemInfo{PURLType: "generic"}
	}

	purl := NewPURL(info.PURLType, "", product, version)

	switch ecosystem {
	case EcosystemMaven:
		if vendor != "" && vendor != ValueANY {
			purl.Namespace = vendor
		}
	case EcosystemNPM:
		if vendor != "" && vendor != ValueANY {
			purl.Namespace = "@" + vendor
		}
	case EcosystemGo:
		if vendor != "" && vendor != ValueANY && vendor != "google" {
			purl.Name = vendor + "/" + product
		}
	case EcosystemDocker:
		if vendor != "" && vendor != ValueANY && vendor != "docker" {
			purl.Namespace = vendor
		}
	}

	return purl, nil
}

// inferVendorProductFromPURL 从 PURL 推断 CPE 的 vendor 和 product
func inferVendorProductFromPURL(purl *PackageURL, ecosystem Ecosystem) (vendor, product string) {
	name := purl.Name
	namespace := purl.Namespace

	switch ecosystem {
	case EcosystemMaven:
		// Maven: namespace 是 groupId, name 是 artifactId
		if namespace != "" {
			// 取 groupId 的第一段作为 vendor
			parts := strings.Split(namespace, ".")
			if len(parts) > 0 {
				vendor = parts[0]
			} else {
				vendor = namespace
			}
		} else {
			vendor = "unknown"
		}
		product = name

	case EcosystemNPM:
		if namespace != "" {
			vendor = strings.TrimPrefix(namespace, "@")
		} else {
			// 取 name 的第一段（scope 或 main name）
			parts := strings.Split(name, "/")
			if len(parts) > 1 {
				vendor = parts[0]
				product = parts[1]
			} else {
				vendor = "npm"
				product = name
			}
		}
		if vendor == "npm" {
			product = name
		}

	case EcosystemGo:
		parts := strings.Split(name, "/")
		if len(parts) >= 2 {
			vendor = parts[0]
			product = parts[len(parts)-1]
		} else {
			vendor = "golang"
			product = name
		}

	case EcosystemPyPI:
		vendor = "python"
		product = name

	case EcosystemNuGet:
		if namespace != "" {
			vendor = namespace
		} else {
			vendor = "microsoft"
		}
		product = name

	case EcosystemDocker:
		if namespace != "" {
			vendor = namespace
		} else {
			parts := strings.Split(name, "/")
			if len(parts) > 1 {
				vendor = parts[0]
				product = parts[1]
			} else {
				vendor = "docker"
				product = name
			}
		}
		if namespace == "" && !strings.Contains(name, "/") {
			vendor = "_"
			product = name
		}

	case EcosystemRubyGems:
		vendor = "rubygems"
		product = name

	case EcosystemCargo:
		vendor = "rust"
		product = name

	case EcosystemComposer:
		if strings.Contains(name, "/") {
			parts := strings.Split(name, "/")
			vendor = parts[0]
			product = parts[1]
		} else {
			vendor = "packagist"
			product = name
		}

	case EcosystemAlpine, EcosystemDebian, EcosystemRPM:
		vendor = string(ecosystem)
		product = name

	default:
		vendor = purl.Type
		product = name
	}

	// 清理：确保 vendor 和 product 不为空
	if vendor == "" {
		vendor = purl.Type
	}
	if product == "" {
		product = name
	}

	return vendor, product
}
