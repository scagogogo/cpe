package cpeskills

import (
	"fmt"
)

// CPEBuilder 提供流式API来构建CPE对象
type CPEBuilder struct {
	wfn *WFN
	err error
}

// NewCPEBuilder 创建一个新的CPEBuilder
func NewCPEBuilder() *CPEBuilder {
	return &CPEBuilder{
		wfn: NewWFN(),
	}
}

// Part 设置CPE的组件类型
func (b *CPEBuilder) Part(part string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	if !ValidPartValues[part] {
		b.err = fmt.Errorf("invalid part value: %s", part)
		return b
	}
	b.wfn.Set(AttrPart, part)
	return b
}

// Vendor 设置CPE的厂商
func (b *CPEBuilder) Vendor(vendor string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrVendor, vendor)
	return b
}

// Product 设置CPE的产品名称
func (b *CPEBuilder) Product(product string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrProduct, product)
	return b
}

// Version 设置CPE的版本号
func (b *CPEBuilder) Version(version string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrVersion, version)
	return b
}

// Update 设置CPE的更新版本
func (b *CPEBuilder) Update(update string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrUpdate, update)
	return b
}

// Edition 设置CPE的版本类型
func (b *CPEBuilder) Edition(edition string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrEdition, edition)
	return b
}

// Language 设置CPE的语言
func (b *CPEBuilder) Language(language string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrLanguage, language)
	return b
}

// SoftwareEdition 设置CPE的软件版本
func (b *CPEBuilder) SoftwareEdition(swEdition string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrSoftwareEdition, swEdition)
	return b
}

// TargetSoftware 设置CPE的目标软件
func (b *CPEBuilder) TargetSoftware(targetSw string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrTargetSoftware, targetSw)
	return b
}

// TargetHardware 设置CPE的目标硬件
func (b *CPEBuilder) TargetHardware(targetHw string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrTargetHardware, targetHw)
	return b
}

// Other 设置CPE的其他属性
func (b *CPEBuilder) Other(other string) *CPEBuilder {
	if b.err != nil {
		return b
	}
	b.wfn.Set(AttrOther, other)
	return b
}

// Application 设置Part为应用程序(a)
func (b *CPEBuilder) Application() *CPEBuilder {
	return b.Part(PartApplicationShort)
}

// OS 设置Part为操作系统(o)
func (b *CPEBuilder) OS() *CPEBuilder {
	return b.Part(PartOSShort)
}

// Hardware 设置Part为硬件(h)
func (b *CPEBuilder) Hardware() *CPEBuilder {
	return b.Part(PartHardwareShort)
}

// Build 构建并返回CPE对象，如果构建过程中有错误则返回nil和错误
func (b *CPEBuilder) Build() (*CPE, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.wfn.ToCPE(), nil
}

// MustBuild 构建并返回CPE对象，如果有错误则panic
func (b *CPEBuilder) MustBuild() *CPE {
	cpe, err := b.Build()
	if err != nil {
		panic(err)
	}
	return cpe
}

// BuildWFN 构建并返回WFN对象
func (b *CPEBuilder) BuildWFN() (*WFN, error) {
	if b.err != nil {
		return nil, b.err
	}
	return b.wfn, nil
}
