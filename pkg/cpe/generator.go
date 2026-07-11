package cpeskills

import (
	"fmt"
	"strings"
)

// GenerateCPE 根据给定的参数生成CPE
// 自动填充缺失的属性为ANY
func GenerateCPE(part, vendor, product, version string) *CPE {
	wfn := NewWFN()
	wfn.Set(AttrPart, part)
	wfn.Set(AttrVendor, vendor)
	wfn.Set(AttrProduct, product)
	wfn.Set(AttrVersion, version)
	return wfn.ToCPE()
}

// GenerateFromTemplate 根据模板CPE和部分参数生成新的CPE
// 未提供的参数将使用模板中的值
func GenerateFromTemplate(template *CPE, overrides map[string]string) *CPE {
	if template == nil {
		template = &CPE{}
	}

	wfn := FromCPE(template)

	for attr, value := range overrides {
		wfn.Set(attr, value)
	}

	return wfn.ToCPE()
}

// FillDefaults 为CPE填充默认值
// 空字段会被填充为ANY(*)
func FillDefaults(cpe *CPE) *CPE {
	if cpe == nil {
		cpe = &CPE{}
	}

	if cpe.Part.ShortName == "" {
		cpe.Part = *PartApplication
	}
	if cpe.Vendor == "" {
		cpe.Vendor = Vendor(ValueANY)
	}
	if cpe.ProductName == "" {
		cpe.ProductName = Product(ValueANY)
	}
	if cpe.Version == "" {
		cpe.Version = Version(ValueANY)
	}
	if cpe.Update == "" {
		cpe.Update = Update(ValueANY)
	}
	if cpe.Edition == "" {
		cpe.Edition = Edition(ValueANY)
	}
	if cpe.Language == "" {
		cpe.Language = Language(ValueANY)
	}
	if cpe.SoftwareEdition == "" {
		cpe.SoftwareEdition = ValueANY
	}
	if cpe.TargetSoftware == "" {
		cpe.TargetSoftware = ValueANY
	}
	if cpe.TargetHardware == "" {
		cpe.TargetHardware = ValueANY
	}
	if cpe.Other == "" {
		cpe.Other = ValueANY
	}

	// 生成CPE 2.3字符串
	if cpe.Cpe23 == "" {
		cpe.Cpe23 = FormatCpe23(cpe)
	}

	return cpe
}

// MergeCPEs 合并两个CPE，优先使用第一个CPE的非空值
// 第二个CPE的非空值用于填充第一个CPE的空值
func MergeCPEs(primary, secondary *CPE) *CPE {
	if primary == nil {
		return FillDefaults(secondary)
	}
	if secondary == nil {
		return FillDefaults(primary)
	}

	result := &CPE{}

	// Part: 优先使用primary
	if primary.Part.ShortName != "" {
		result.Part = primary.Part
	} else {
		result.Part = secondary.Part
	}

	// 其他字段: 优先使用primary，空值使用secondary
	if primary.Vendor != "" {
		result.Vendor = primary.Vendor
	} else {
		result.Vendor = secondary.Vendor
	}

	if primary.ProductName != "" {
		result.ProductName = primary.ProductName
	} else {
		result.ProductName = secondary.ProductName
	}

	if primary.Version != "" {
		result.Version = primary.Version
	} else {
		result.Version = secondary.Version
	}

	if primary.Update != "" {
		result.Update = primary.Update
	} else {
		result.Update = secondary.Update
	}

	if primary.Edition != "" {
		result.Edition = primary.Edition
	} else {
		result.Edition = secondary.Edition
	}

	if primary.Language != "" {
		result.Language = primary.Language
	} else {
		result.Language = secondary.Language
	}

	if primary.SoftwareEdition != "" {
		result.SoftwareEdition = primary.SoftwareEdition
	} else {
		result.SoftwareEdition = secondary.SoftwareEdition
	}

	if primary.TargetSoftware != "" {
		result.TargetSoftware = primary.TargetSoftware
	} else {
		result.TargetSoftware = secondary.TargetSoftware
	}

	if primary.TargetHardware != "" {
		result.TargetHardware = primary.TargetHardware
	} else {
		result.TargetHardware = secondary.TargetHardware
	}

	if primary.Other != "" {
		result.Other = primary.Other
	} else {
		result.Other = secondary.Other
	}

	result.Cpe23 = FormatCpe23(result)

	return result
}

// FuzzyGenerateCPE 根据模糊输入生成CPE
// 自动标准化输入字符串（转换为小写，替换空格为下划线等）
func FuzzyGenerateCPE(part, vendor, product, version string) *CPE {
	wfn := NewWFN()
	wfn.Set(AttrPart, NormalizeComponent(part))
	wfn.Set(AttrVendor, NormalizeComponent(vendor))
	wfn.Set(AttrProduct, NormalizeComponent(product))
	wfn.Set(AttrVersion, NormalizeComponent(version))
	return wfn.ToCPE()
}

// RandomCPE 生成一个随机的CPE用于测试
// 生成的CPE仅用于测试目的，不表示真实的IT产品
func RandomCPE() *CPE {
	return GenerateCPE("a", "test_vendor", "test_product", "1.0")
}

// Parse 解析任意格式的CPE字符串(2.2或2.3)
func Parse(cpeStr string) (*CPE, error) {
	if strings.HasPrefix(cpeStr, "cpe:2.3:") || strings.HasPrefix(cpeStr, "cpe:/") {
		// 尝试2.3格式
		if strings.HasPrefix(cpeStr, "cpe:2.3:") {
			return ParseCpe23(cpeStr)
		}
		// 2.2格式
		return ParseCpe22(cpeStr)
	}

	return nil, fmt.Errorf("unable to determine CPE format: %s", cpeStr)
}