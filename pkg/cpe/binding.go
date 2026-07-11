package cpeskills

import (
	"fmt"
	"strings"
)

// BindToFS 将WFN绑定为CPE 2.3 FS(Formatted String)格式
// 按照 NISTIR 7695 规范实现
func BindToFS(w *WFN) string {
	if w == nil {
		return ""
	}

	parts := []string{
		"cpe", "2.3",
		bindAttributeValueToFS(w.Get(AttrPart)),
		bindAttributeValueToFS(w.Get(AttrVendor)),
		bindAttributeValueToFS(w.Get(AttrProduct)),
		bindAttributeValueToFS(w.Get(AttrVersion)),
		bindAttributeValueToFS(w.Get(AttrUpdate)),
		bindAttributeValueToFS(w.Get(AttrEdition)),
		bindAttributeValueToFS(w.Get(AttrLanguage)),
		bindAttributeValueToFS(w.Get(AttrSoftwareEdition)),
		bindAttributeValueToFS(w.Get(AttrTargetSoftware)),
		bindAttributeValueToFS(w.Get(AttrTargetHardware)),
		bindAttributeValueToFS(w.Get(AttrOther)),
	}

	return strings.Join(parts, ":")
}

// UnbindFS 将CPE 2.3 FS格式字符串解绑为WFN
func UnbindFS(fs string) (*WFN, error) {
	if !strings.HasPrefix(fs, "cpe:2.3:") {
		return nil, fmt.Errorf("invalid CPE 2.3 FS format: %s", fs)
	}

	parts := strings.Split(fs, ":")
	if len(parts) != 13 {
		return nil, fmt.Errorf("invalid CPE 2.3 FS format, expected 13 parts: %s", fs)
	}

	return &WFN{
		Part:            unbindFSComponent(parts[2]),
		Vendor:          unbindFSComponent(parts[3]),
		Product:         unbindFSComponent(parts[4]),
		Version:         unbindFSComponent(parts[5]),
		Update:          unbindFSComponent(parts[6]),
		Edition:         unbindFSComponent(parts[7]),
		Language:        unbindFSComponent(parts[8]),
		SoftwareEdition: unbindFSComponent(parts[9]),
		TargetSoftware:  unbindFSComponent(parts[10]),
		TargetHardware:  unbindFSComponent(parts[11]),
		Other:           unbindFSComponent(parts[12]),
	}, nil
}

// BindToURI 将WFN绑定为CPE 2.2 URI格式
// 按照 NISTIR 7695 规范实现
func BindToURI(w *WFN) string {
	if w == nil {
		return ""
	}

	result := "cpe:/"

	// 主字段: part:vendor:product:version:update
	mainParts := []string{
		bindAttributeValueToURI(w.Get(AttrPart)),
		bindAttributeValueToURI(w.Get(AttrVendor)),
		bindAttributeValueToURI(w.Get(AttrProduct)),
		bindAttributeValueToURI(w.Get(AttrVersion)),
		bindAttributeValueToURI(w.Get(AttrUpdate)),
	}
	result += strings.Join(mainParts, ":")

	// 检查是否有扩展属性
	edition := w.Get(AttrEdition)
	language := w.Get(AttrLanguage)
	swEdition := w.Get(AttrSoftwareEdition)
	targetSw := w.Get(AttrTargetSoftware)
	targetHw := w.Get(AttrTargetHardware)
	other := w.Get(AttrOther)

	hasExtended := edition != ValueANY || language != ValueANY ||
		swEdition != ValueANY || targetSw != ValueANY ||
		targetHw != ValueANY || other != ValueANY

	if hasExtended {
		// 打包扩展属性
		packed := packExtendedAttributes(
			bindAttributeValueToURI(edition),
			bindAttributeValueToURI(language),
			bindAttributeValueToURI(swEdition),
			bindAttributeValueToURI(targetSw),
			bindAttributeValueToURI(targetHw),
			bindAttributeValueToURI(other),
		)
		if packed != "" {
			result += ":" + packed
		}
	}

	return result
}

// UnbindURI 将CPE 2.2 URI格式字符串解绑为WFN
func UnbindURI(uri string) (*WFN, error) {
	if !strings.HasPrefix(uri, "cpe:/") {
		return nil, fmt.Errorf("invalid CPE 2.2 URI format: %s", uri)
	}

	content := strings.TrimPrefix(uri, "cpe:/")
	parts := strings.Split(content, ":")

	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("invalid CPE 2.2 URI format: %s", uri)
	}

	wfn := NewWFN()

	// 解析 part
	wfn.Part = unbindURIComponent(parts[0])

	// 解析 vendor
	if len(parts) > 1 {
		wfn.Vendor = unbindURIComponent(parts[1])
	}

	// 解析 product
	if len(parts) > 2 {
		wfn.Product = unbindURIComponent(parts[2])
	}

	// 解析 version
	if len(parts) > 3 {
		wfn.Version = unbindURIComponent(parts[3])
	}

	// 解析 update
	if len(parts) > 4 {
		wfn.Update = unbindURIComponent(parts[4])
	}

	// 检查扩展属性
	for i := 5; i < len(parts); i++ {
		if strings.Contains(parts[i], "~") {
			extParts := strings.Split(parts[i], "~")

			// edition (第一个扩展部分)
			if len(extParts) > 0 && extParts[0] != "" {
				wfn.Edition = unbindURIComponent(extParts[0])
			}

			// language (索引3, 但在2.2格式中位置不同)
			if len(extParts) > 3 && extParts[3] != "" {
				wfn.Language = unbindURIComponent(extParts[3])
			}

			// sw_edition
			if len(extParts) > 4 && extParts[4] != "" {
				wfn.SoftwareEdition = unbindURIComponent(extParts[4])
			}

			// target_sw
			if len(extParts) > 5 && extParts[5] != "" {
				wfn.TargetSoftware = unbindURIComponent(extParts[5])
			}

			// target_hw
			if len(extParts) > 6 && extParts[6] != "" {
				wfn.TargetHardware = unbindURIComponent(extParts[6])
			}

			// other
			if len(extParts) > 7 && extParts[7] != "" {
				wfn.Other = unbindURIComponent(extParts[7])
			}

			break
		}
	}

	// 如果没有扩展格式，处理edition和language
	if len(parts) > 5 && !strings.Contains(strings.Join(parts[5:], ":"), "~") {
		if len(parts) > 5 && parts[5] != "" {
			wfn.Edition = unbindURIComponent(parts[5])
		}
		if len(parts) > 6 && parts[6] != "" {
			wfn.Language = unbindURIComponent(parts[6])
		}
	}

	return wfn, nil
}

// ConvertURIToFS 将CPE 2.2 URI格式字符串转换为CPE 2.3 FS格式字符串
func ConvertURIToFS(uri string) (string, error) {
	wfn, err := UnbindURI(uri)
	if err != nil {
		return "", err
	}
	return BindToFS(wfn), nil
}

// ConvertFSToURI 将CPE 2.3 FS格式字符串转换为CPE 2.2 URI格式字符串
func ConvertFSToURI(fs string) (string, error) {
	wfn, err := UnbindFS(fs)
	if err != nil {
		return "", err
	}
	return BindToURI(wfn), nil
}

// convertCpe22ToCpe23 将CPE 2.2格式转换为CPE 2.3格式（向后兼容）
func convertCpe22ToCpe23(cpe22 string) string {
	result, err := ConvertURIToFS(cpe22)
	if err != nil {
		return ""
	}
	return result
}

// bindAttributeValueToFS 将WFN属性值绑定为FS格式组件
func bindAttributeValueToFS(value string) string {
	if isLogicalValue(value) {
		return value
	}
	if value == "" {
		return ValueANY
	}
	return escapeForFS(value)
}

// unbindFSComponent 将FS格式组件解绑为WFN属性值
func unbindFSComponent(component string) string {
	if isLogicalValue(component) {
		return component
	}
	if component == "" {
		return ValueANY
	}
	return unescapeFromFS(component)
}

// bindAttributeValueToURI 将WFN属性值绑定为URI格式组件
func bindAttributeValueToURI(value string) string {
	if isLogicalValue(value) {
		return value
	}
	if value == "" {
		return ValueANY
	}
	return escapeForURI(value)
}

// unbindURIComponent 将URI格式组件解绑为WFN属性值
func unbindURIComponent(component string) string {
	if isLogicalValue(component) {
		return component
	}
	if component == "" {
		return ValueANY
	}
	return unescapeFromURI(component)
}
