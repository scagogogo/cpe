package cpe

import (
	"fmt"
	"regexp"
	"strings"
)

// WFN (Well-Formed Name) 表示CPE的规范化内部表示
// WFN是CPE的内部规范表示形式，用于存储CPE各个组成部分的值
// 一个完整的WFN包含以下11个属性：part, vendor, product, version, update, edition, language,
// softwareEdition, targetSoftware, targetHardware和other
type WFN struct {
	Part            string // 组件类型: a(应用程序)、o(操作系统)、h(硬件设备)
	Vendor          string // 厂商名称
	Product         string // 产品名称
	Version         string // 版本号
	Update          string // 更新版本
	Edition         string // 版本
	Language        string // 语言
	SoftwareEdition string // 软件版本
	TargetSoftware  string // 目标软件
	TargetHardware  string // 目标硬件
	Other           string // 其他信息
}

// FromCPE 从CPE结构体创建WFN
// 本方法将CPE结构体转换为规范化的WFN格式，用于内部处理和比较
//
// 参数:
//   - cpe: CPE结构体指针，包含各个属性的值
//
// 返回值:
//   - *WFN: 转换后的WFN结构体指针
//
// 示例:
//
//	cpe := &CPE{
//	  Part: *PartApplication,
//	  Vendor: "microsoft",
//	  ProductName: "windows",
//	  Version: "10",
//	}
//	wfn := FromCPE(cpe)
//	fmt.Println(wfn.Part)     // 输出: "a"
//	fmt.Println(wfn.Vendor)   // 输出: "microsoft"
//	fmt.Println(wfn.Product)  // 输出: "windows"
//	fmt.Println(wfn.Version)  // 输出: "10"
func FromCPE(cpe *CPE) *WFN {
	return &WFN{
		Part:            cpe.Part.ShortName,
		Vendor:          string(cpe.Vendor),
		Product:         string(cpe.ProductName),
		Version:         string(cpe.Version),
		Update:          string(cpe.Update),
		Edition:         string(cpe.Edition),
		Language:        string(cpe.Language),
		SoftwareEdition: cpe.SoftwareEdition,
		TargetSoftware:  cpe.TargetSoftware,
		TargetHardware:  cpe.TargetHardware,
		Other:           cpe.Other,
	}
}

// ToCPE 转换WFN为CPE结构体
// 本方法将WFN转换回CPE结构体，用于外部使用和展示
//
// 返回值:
//   - *CPE: 转换后的CPE结构体指针，包含从WFN提取的所有属性值
//
// 示例:
//
//	wfn := &WFN{
//	  Part: "a",
//	  Vendor: "microsoft",
//	  Product: "windows",
//	  Version: "10",
//	}
//	cpe := wfn.ToCPE()
//	fmt.Println(cpe.Part.Name)      // 输出: "Application"
//	fmt.Println(string(cpe.Vendor)) // 输出: "microsoft"
//	fmt.Println(cpe.Cpe23)          // 输出CPE 2.3格式字符串
//
// 注意:
//   - 方法会自动设置CPE.Cpe23字段，生成CPE 2.3格式字符串
//   - 如果WFN.Part不是有效值(a/h/o)，默认为应用程序(a)
func (w *WFN) ToCPE() *CPE {
	cpe := &CPE{
		Vendor:          Vendor(w.Vendor),
		ProductName:     Product(w.Product),
		Version:         Version(w.Version),
		Update:          Update(w.Update),
		Edition:         Edition(w.Edition),
		Language:        Language(w.Language),
		SoftwareEdition: w.SoftwareEdition,
		TargetSoftware:  w.TargetSoftware,
		TargetHardware:  w.TargetHardware,
		Other:           w.Other,
	}

	// 设置Part
	switch w.Part {
	case "a":
		cpe.Part = *PartApplication
	case "h":
		cpe.Part = *PartHardware
	case "o":
		cpe.Part = *PartOperationSystem
	default:
		cpe.Part = *PartApplication
	}

	// 生成CPE 2.3格式字符串
	cpe.Cpe23 = w.ToCPE23String()

	return cpe
}

// FromCPE23String 从CPE 2.3格式字符串创建WFN
// 本方法解析CPE 2.3格式的字符串，将其转换为WFN结构体
//
// 参数:
//   - cpe23: 符合CPE 2.3规范的字符串，例如"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
//
// 返回值:
//   - *WFN: 解析成功返回WFN结构体指针
//   - error: 解析失败返回错误信息
//
// 示例:
//
//	wfn, err := FromCPE23String("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
//	if err != nil {
//	  panic(err)
//	}
//	fmt.Println(wfn.Part)     // 输出: "a"
//	fmt.Println(wfn.Vendor)   // 输出: "microsoft"
//	fmt.Println(wfn.Product)  // 输出: "windows"
//	fmt.Println(wfn.Version)  // 输出: "10"
//
// 错误情况:
//   - 如果字符串不以"cpe:2.3:"开头，返回格式错误
//   - 如果字符串不包含13个部分(以冒号分隔)，返回格式错误
//
// 注意:
//   - 方法会自动对每个字段进行反转义处理
func FromCPE23String(cpe23 string) (*WFN, error) {
	// 移除cpe:2.3:前缀
	if !strings.HasPrefix(cpe23, "cpe:2.3:") {
		return nil, fmt.Errorf("invalid CPE 2.3 format: %s", cpe23)
	}

	parts := strings.Split(cpe23, ":")
	if len(parts) != 13 {
		return nil, fmt.Errorf("invalid CPE 2.3 format, expected 13 parts: %s", cpe23)
	}

	wfn := &WFN{
		Part:            parts[2],
		Vendor:          unescapeValue(parts[3]),
		Product:         unescapeValue(parts[4]),
		Version:         unescapeValue(parts[5]),
		Update:          unescapeValue(parts[6]),
		Edition:         unescapeValue(parts[7]),
		Language:        unescapeValue(parts[8]),
		SoftwareEdition: unescapeValue(parts[9]),
		TargetSoftware:  unescapeValue(parts[10]),
		TargetHardware:  unescapeValue(parts[11]),
		Other:           unescapeValue(parts[12]),
	}

	return wfn, nil
}

// FromCPE22String 从CPE 2.2格式字符串创建WFN
// 本方法解析CPE 2.2格式的字符串，将其转换为WFN结构体
// 内部实现是先将CPE 2.2转换为CPE 2.3格式，再调用FromCPE23String方法
//
// 参数:
//   - cpe22: 符合CPE 2.2规范的字符串，例如"cpe:/a:microsoft:windows:10"
//
// 返回值:
//   - *WFN: 解析成功返回WFN结构体指针
//   - error: 解析失败返回错误信息
//
// 示例:
//
//	wfn, err := FromCPE22String("cpe:/a:microsoft:windows:10")
//	if err != nil {
//	  panic(err)
//	}
//	fmt.Println(wfn.Part)     // 输出: "a"
//	fmt.Println(wfn.Vendor)   // 输出: "microsoft"
//	fmt.Println(wfn.Product)  // 输出: "windows"
//	fmt.Println(wfn.Version)  // 输出: "10"
//
// 错误情况:
//   - 如果转换后的CPE 2.3格式字符串无效，会返回FromCPE23String传递的错误
//
// 注意:
//   - 该方法依赖convertCpe22ToCpe23函数，该函数将CPE 2.2格式转换为CPE 2.3格式
func FromCPE22String(cpe22 string) (*WFN, error) {
	// 转换成CPE 2.3格式，再解析
	cpe23 := convertCpe22ToCpe23(cpe22)
	return FromCPE23String(cpe23)
}

// ToCPE23String 转换WFN为CPE 2.3格式字符串
// 本方法将WFN结构体转换为标准的CPE 2.3格式字符串
//
// 返回值:
//   - string: 符合CPE 2.3规范的字符串，例如"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
//
// 示例:
//
//	wfn := &WFN{
//	  Part: "a",
//	  Vendor: "microsoft",
//	  Product: "windows",
//	  Version: "10",
//	}
//	cpe23 := wfn.ToCPE23String()
//	fmt.Println(cpe23) // 输出: "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
//
// 注意:
//   - 方法会自动对每个字段进行转义处理，使用escapeValue函数
//   - 所有字段之间用冒号(:)分隔，共有13部分
//   - 返回的字符串始终以"cpe:2.3:"开头
func (w *WFN) ToCPE23String() string {
	parts := []string{
		"cpe", "2.3",
		w.Part,
		escapeValue(w.Vendor),
		escapeValue(w.Product),
		escapeValue(w.Version),
		escapeValue(w.Update),
		escapeValue(w.Edition),
		escapeValue(w.Language),
		escapeValue(w.SoftwareEdition),
		escapeValue(w.TargetSoftware),
		escapeValue(w.TargetHardware),
		escapeValue(w.Other),
	}

	return strings.Join(parts, ":")
}

// ToCPE22String 转换WFN为CPE 2.2格式字符串
// 本方法将WFN结构体转换为标准的CPE 2.2格式字符串
//
// 返回值:
//   - string: 符合CPE 2.2规范的字符串，例如"cpe:/a:microsoft:windows:10"
//
// 示例:
//
//	wfn := &WFN{
//	  Part: "a",
//	  Vendor: "microsoft",
//	  Product: "windows",
//	  Version: "10",
//	  Update: "sp1",
//	  Edition: "pro",
//	  Language: "zh-cn",
//	}
//	cpe22 := wfn.ToCPE22String()
//	fmt.Println(cpe22) // 输出: "cpe:/a:microsoft:windows:10:sp1:pro~zh-cn"
//
// 注意:
//   - CPE 2.2格式与CPE 2.3格式不完全兼容，部分字段可能无法完整表示
//   - 主要部分(Part, Vendor, Product, Version, Update)用冒号分隔
//   - 扩展属性(如Edition等)使用波浪线(~)分隔
//   - 方法会自动移除末尾空值的扩展属性
//   - 使用escapeValueForCpe22函数进行转义，转义规则与CPE 2.3不同
func (w *WFN) ToCPE22String() string {
	cpePrefix := "cpe:/"
	mainParts := []string{
		w.Part,
		escapeValueForCpe22(w.Vendor),
		escapeValueForCpe22(w.Product),
		escapeValueForCpe22(w.Version),
		escapeValueForCpe22(w.Update),
	}

	// 将主要部分组合成CPE 2.2格式
	result := cpePrefix + strings.Join(mainParts, ":")

	// 如果有扩展属性，添加到结果中
	if w.Edition != "" || w.Language != "" || w.SoftwareEdition != "" ||
		w.TargetSoftware != "" || w.TargetHardware != "" || w.Other != "" {

		extParts := []string{
			escapeValueForCpe22(w.Edition),
			"", // CPE 2.2没有明确的位置给这个字段
			"", // CPE 2.2没有明确的位置给这个字段
			escapeValueForCpe22(w.Language),
			escapeValueForCpe22(w.SoftwareEdition),
			escapeValueForCpe22(w.TargetSoftware),
			escapeValueForCpe22(w.TargetHardware),
			escapeValueForCpe22(w.Other),
		}

		// 移除末尾的空值
		for i := len(extParts) - 1; i >= 0; i-- {
			if extParts[i] != "" {
				extParts = extParts[:i+1]
				break
			}
		}

		if len(extParts) > 0 {
			result += ":" + strings.Join(extParts, "~")
		}
	}

	return result
}

// escapeValue 对CPE 2.3格式的值进行转义
// 本函数处理CPE 2.3格式中特殊字符的转义
//
// 参数:
//   - value: 需要转义的原始字符串值
//
// 返回值:
//   - string: 转义后的字符串
//
// 示例:
//
//	escaped := escapeValue("windows.server")
//	fmt.Println(escaped) // 输出: "windows\.server"
//
//	// 版本号中的点号不进行转义
//	escaped = escapeValue("2.0.1")
//	fmt.Println(escaped) // 输出: "2.0.1"
//
// 转义规则:
//   - 特殊值 "*"(ANY), "-"(NA) 和空字符串保持不变
//   - 点号(.)会被转义为"\."，除非出现在符合版本格式的字符串中
//   - 冒号(:)会被转义为"\:"
//
// 注意:
//   - 函数会识别版本号格式(如1.2.3)，在这种情况下点号不做转义
//   - 这是为了保持版本号的可读性和一致性
func escapeValue(value string) string {
	// 如果是特殊值或空值，不需要转义
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 检查是否是版本字段，版本字段中的点不做双重转义
	// 通常版本字段的格式为数字.数字.数字
	isVersion := false
	if len(value) >= 3 {
		versionPattern := regexp.MustCompile(`^\d+(\.\d+)+$`)
		isVersion = versionPattern.MatchString(value)
	}

	// 转义值
	escaped := value

	if !isVersion {
		// 转义点号，除非在版本号中
		escaped = strings.ReplaceAll(escaped, ".", "\\.")
	}

	// 转义其他特殊字符
	escaped = strings.ReplaceAll(escaped, ":", "\\:")

	return escaped
}

// unescapeValue 对CPE 2.3格式的值进行反转义
// 本函数处理CPE 2.3格式中特殊字符的反转义，是escapeValue的逆操作
//
// 参数:
//   - value: 需要反转义的字符串
//
// 返回值:
//   - string: 反转义后的原始字符串
//
// 示例:
//
//	original := unescapeValue("windows\\.server")
//	fmt.Println(original) // 输出: "windows.server"
//
//	original = unescapeValue("2\\.0\\.1")
//	fmt.Println(original) // 输出: "2.0.1"
//
// 反转义规则:
//   - 特殊值 "*"(ANY), "-"(NA) 和空字符串保持不变
//   - 所有形如"\x"的字符序列会被替换为"x"，其中x可以是任何字符
//
// 注意:
//   - 使用正则表达式识别和替换所有转义序列
//   - 这个函数可以处理所有通过escapeValue函数转义的字符串
func unescapeValue(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 使用正则表达式识别转义序列
	re := regexp.MustCompile(`\\(.)`)
	return re.ReplaceAllString(value, "$1")
}

// escapeValueForCpe22 对CPE 2.2格式的值进行转义
// 本函数处理CPE 2.2格式中特殊字符的转义，其规则与CPE 2.3不同
//
// 参数:
//   - value: 需要转义的原始字符串值
//
// 返回值:
//   - string: 转义后的字符串，符合CPE 2.2格式要求
//
// 示例:
//
//	escaped := escapeValueForCpe22("windows/server")
//	fmt.Println(escaped) // 输出: "windows%2fserver"
//
//	escaped = escapeValueForCpe22("demo:test")
//	fmt.Println(escaped) // 输出: "demo%3atest"
//
// 转义规则:
//   - 特殊值 "*"(ANY), "-"(NA) 和空字符串保持不变
//   - 反斜杠(\)转义为"\\"
//   - 冒号(:)转义为"%3a"
//   - 斜杠(/)转义为"%2f"
//   - 波浪线(~)转义为"%7e"
//
// 注意:
//   - CPE 2.2使用百分号编码(percent-encoding)来表示特殊字符，而不是反斜杠转义
//   - 这种格式更接近URI编码，使CPE更容易嵌入到URL中
func escapeValueForCpe22(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 替换特殊字符
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		":", "%3a",
		"/", "%2f",
		"~", "%7e",
	)

	return replacer.Replace(value)
}

// Match 比较两个WFN是否匹配
// 本方法检查当前WFN与另一个WFN是否匹配，匹配规则遵循CPE规范
//
// 参数:
//   - other: 另一个WFN结构体指针，用于与当前WFN比较
//
// 返回值:
//   - bool: 如果匹配返回true，否则返回false
//
// 示例:
//
//	wfn1 := &WFN{
//	  Part: "a",
//	  Vendor: "microsoft",
//	  Product: "windows",
//	  Version: "*", // 任意版本
//	}
//
//	wfn2 := &WFN{
//	  Part: "a",
//	  Vendor: "microsoft",
//	  Product: "windows",
//	  Version: "10",
//	}
//
//	fmt.Println(wfn1.Match(wfn2)) // 输出: true
//	fmt.Println(wfn2.Match(wfn1)) // 输出: true
//
// 匹配规则:
//   - 如果两个WFN的所有属性都匹配，则这两个WFN匹配
//   - 单个属性的匹配规则通过matchWFNAttribute函数定义
//   - 属性为"*"表示ANY，可以匹配任何值
//   - 如果两个属性都是"-"(NA)，则它们匹配
//   - 其他情况要求精确匹配
func (w *WFN) Match(other *WFN) bool {
	// 检查Part
	if !matchWFNAttribute(w.Part, other.Part) {
		return false
	}

	// 检查其他属性
	return matchWFNAttribute(w.Vendor, other.Vendor) &&
		matchWFNAttribute(w.Product, other.Product) &&
		matchWFNAttribute(w.Version, other.Version) &&
		matchWFNAttribute(w.Update, other.Update) &&
		matchWFNAttribute(w.Edition, other.Edition) &&
		matchWFNAttribute(w.Language, other.Language) &&
		matchWFNAttribute(w.SoftwareEdition, other.SoftwareEdition) &&
		matchWFNAttribute(w.TargetSoftware, other.TargetSoftware) &&
		matchWFNAttribute(w.TargetHardware, other.TargetHardware) &&
		matchWFNAttribute(w.Other, other.Other)
}

// matchWFNAttribute 匹配WFN的单个属性
// 本函数检查两个WFN属性值是否匹配，遵循CPE规范的匹配规则
//
// 参数:
//   - a: 第一个属性值
//   - b: 第二个属性值
//
// 返回值:
//   - bool: 如果匹配返回true，否则返回false
//
// 示例:
//
//	// ANY匹配任何值
//	fmt.Println(matchWFNAttribute("*", "windows")) // 输出: true
//
//	// NA匹配NA
//	fmt.Println(matchWFNAttribute("-", "-")) // 输出: true
//
//	// 精确匹配
//	fmt.Println(matchWFNAttribute("windows", "windows")) // 输出: true
//	fmt.Println(matchWFNAttribute("windows", "linux")) // 输出: false
//
// 匹配规则:
//   - 如果任一属性为"*"(ANY)，则匹配
//   - 如果两个属性都是"-"(NA)，则匹配
//   - 其他情况要求精确匹配(区分大小写)
func matchWFNAttribute(a, b string) bool {
	// 如果有一个是ANY (*), 则匹配
	if a == "*" || b == "*" {
		return true
	}

	// 如果两个值都是NA (-), 则匹配
	if a == "-" && b == "-" {
		return true
	}

	// 精确匹配
	return a == b
}
