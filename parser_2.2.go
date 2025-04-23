package cpe

import (
	"regexp"
	"strings"
)

const CPE22Header = "cpe"

/**
 * ParseCpe22 解析CPE 2.2字符串格式并转换为CPE结构体
 *
 * CPE 2.2是较早的CPE格式标准，具有特定的语法规则。
 * 格式为：cpe:/[part]:[vendor]:[product]:[version]:[update]:[edition]:[language]
 * 有时会包含扩展格式：cpe:/[part]:[vendor]:[product]:[version]:[update]:[edition]:[language]:~[sw_edition]~[target_sw]~[target_hw]~[other]
 *
 * @param cpe22 CPE 2.2格式的字符串，例如 "cpe:/a:apache:tomcat:8.5.0"或扩展格式
 * @return (*CPE, error) 成功时返回解析后的CPE结构体指针，失败时返回nil和错误
 *
 * @error 当输入字符串不是以"cpe:/"开头时，返回InvalidFormatError
 * @error 当part字段值不是a、h或o时，返回InvalidPartError
 *
 * 示例:
 *   ```go
 *   // 解析基本格式的CPE 2.2
 *   tomcatCPE, err := cpe.ParseCpe22("cpe:/a:apache:tomcat:8.5.0")
 *   if err != nil {
 *       log.Fatalf("解析CPE失败: %v", err)
 *   }
 *   fmt.Printf("厂商: %s, 产品: %s, 版本: %s\n", tomcatCPE.Vendor, tomcatCPE.ProductName, tomcatCPE.Version)
 *   // 输出: 厂商: apache, 产品: tomcat, 版本: 8.5.0
 *
 *   // 解析带扩展的CPE 2.2
 *   mysqlCPE, err := cpe.ParseCpe22("cpe:/a:mysql:mysql:5.7.12:::~~~enterprise~")
 *   if err != nil {
 *       log.Fatalf("解析CPE失败: %v", err)
 *   }
 *   fmt.Printf("厂商: %s, 产品: %s, 版本: %s, 软件版本: %s\n",
 *              mysqlCPE.Vendor, mysqlCPE.ProductName, mysqlCPE.Version, mysqlCPE.SoftwareEdition)
 *   // 输出: 厂商: mysql, 产品: mysql, 版本: 5.7.12, 软件版本: enterprise
 *   ```
 */
func ParseCpe22(cpe22 string) (*CPE, error) {
	if !strings.HasPrefix(cpe22, "cpe:/") {
		return nil, NewInvalidFormatError(cpe22)
	}

	// 移除前缀"cpe:/"
	withoutPrefix := cpe22[5:]

	// 按照:分割
	parts := strings.Split(withoutPrefix, ":")

	// 至少要有part元素
	if len(parts) < 1 {
		return nil, NewInvalidFormatError(cpe22)
	}

	// 将2.2格式转换为结构体
	cpe := &CPE{
		Cpe23: convertCpe22ToCpe23(cpe22),
	}

	// 解析Part
	if len(parts) > 0 && parts[0] != "" {
		switch parts[0] {
		case "a":
			cpe.Part = *PartApplication
		case "h":
			cpe.Part = *PartHardware
		case "o":
			cpe.Part = *PartOperationSystem
		default:
			return nil, NewInvalidPartError(parts[0])
		}
	}

	// 解析Vendor
	if len(parts) > 1 {
		cpe.Vendor = Vendor(unescapeCpe22Value(parts[1]))
	}

	// 解析Product
	if len(parts) > 2 {
		cpe.ProductName = Product(unescapeCpe22Value(parts[2]))
	}

	// 解析Version
	if len(parts) > 3 {
		cpe.Version = Version(unescapeCpe22Value(parts[3]))
	}

	// 解析Update
	if len(parts) > 4 {
		cpe.Update = Update(unescapeCpe22Value(parts[4]))
	}

	// 解析Edition
	if len(parts) > 5 && !strings.Contains(parts[5], "~") {
		cpe.Edition = Edition(unescapeCpe22Value(parts[5]))
	}

	// 解析Language
	if len(parts) > 6 && !strings.Contains(parts[5], "~") && !strings.Contains(parts[6], "~") {
		cpe.Language = Language(unescapeCpe22Value(parts[6]))
	}

	// 处理扩展格式，有些2.2格式使用~分隔后续字段
	for i := 5; i < len(parts); i++ {
		if strings.Contains(parts[i], "~") {
			extParts := strings.Split(parts[i], "~")

			// 如果这是第5个部分，第一个扩展部分是Edition
			if i == 5 && len(extParts) > 0 && extParts[0] != "" {
				cpe.Edition = Edition(unescapeCpe22Value(extParts[0]))
			}

			// 第4个扩展部分（索引3）是Language
			if len(extParts) > 3 && extParts[3] != "" {
				cpe.Language = Language(unescapeCpe22Value(extParts[3]))
			}

			// 其他扩展字段
			if len(extParts) > 4 && extParts[4] != "" {
				cpe.SoftwareEdition = unescapeCpe22Value(extParts[4])
			}
			if len(extParts) > 5 && extParts[5] != "" {
				cpe.TargetSoftware = unescapeCpe22Value(extParts[5])
			}
			if len(extParts) > 6 && extParts[6] != "" {
				cpe.TargetHardware = unescapeCpe22Value(extParts[6])
			}
			if len(extParts) > 7 && extParts[7] != "" {
				cpe.Other = unescapeCpe22Value(extParts[7])
			}

			break
		}
	}

	return cpe, nil
}

/**
 * FormatCpe22 将CPE对象格式化为CPE 2.2字符串
 *
 * 根据CPE结构体的内容生成符合CPE 2.2标准格式的字符串表示。
 * 支持生成基本格式和扩展格式（带波浪线分隔的附加字段）。
 *
 * @param cpe *CPE CPE结构体指针，包含要格式化的CPE信息，不能为nil
 * @return string 符合CPE 2.2标准的格式化字符串
 *
 * 注意事项：
 *   - 如果输入为nil，返回空字符串
 *   - 线程安全：此函数不修改输入参数，可并发调用
 *   - 性能考虑：字段值中特殊字符的转义会增加少量处理开销
 *   - 格式细节：空字段会被替换为"*"，特殊字符会被转义
 *
 * 示例:
 *   ```go
 *   // 创建并格式化基本CPE
 *   cpe := &cpe.CPE{
 *       Part:        *cpe.PartApplication,
 *       Vendor:      cpe.Vendor("apache"),
 *       ProductName: cpe.Product("tomcat"),
 *       Version:     cpe.Version("8.5.0"),
 *   }
 *   cpe22String := cpe.FormatCpe22(cpe)
 *   fmt.Println(cpe22String)
 *   // 输出: cpe:/a:apache:tomcat:8.5.0
 *
 *   // 创建并格式化带扩展字段的CPE
 *   cpe := &cpe.CPE{
 *       Part:           *cpe.PartApplication,
 *       Vendor:         cpe.Vendor("mysql"),
 *       ProductName:    cpe.Product("mysql"),
 *       Version:        cpe.Version("5.7.12"),
 *       SoftwareEdition: "enterprise",
 *   }
 *   cpe22String := cpe.FormatCpe22(cpe)
 *   fmt.Println(cpe22String)
 *   // 输出: cpe:/a:mysql:mysql:5.7.12:::~~~enterprise~~~
 *   ```
 *
 * @see ParseCpe22 用于解析CPE 2.2字符串为CPE结构体
 * @see escapeCpe22Value 用于转义CPE 2.2中的特殊字符
 */
func FormatCpe22(cpe *CPE) string {
	if cpe == nil {
		return ""
	}

	// 获取Part简写
	partShortName := cpe.Part.ShortName
	if partShortName == "" {
		partShortName = "*"
	}

	// 确保所有字段都有值，如果为空则使用通配符"*"
	vendor := string(cpe.Vendor)
	if vendor == "" {
		vendor = "*"
	}

	productName := string(cpe.ProductName)
	if productName == "" {
		productName = "*"
	}

	version := string(cpe.Version)
	if version == "" {
		version = "*"
	}

	update := string(cpe.Update)
	if update == "" {
		update = "*"
	}

	edition := string(cpe.Edition)
	if edition == "" {
		edition = "*"
	}

	language := string(cpe.Language)
	if language == "" {
		language = "*"
	}

	// 构建基本CPE 2.2字符串
	parts := []string{
		"cpe:/",
		partShortName,
		":",
		escapeCpe22Value(vendor),
		":",
		escapeCpe22Value(productName),
		":",
		escapeCpe22Value(version),
	}

	// 添加Update如果不是*
	if update != "*" {
		parts = append(parts, ":", escapeCpe22Value(update))
	} else if edition != "*" || language != "*" ||
		cpe.SoftwareEdition != "" || cpe.TargetSoftware != "" ||
		cpe.TargetHardware != "" || cpe.Other != "" {
		parts = append(parts, ":")
	}

	// 添加Edition如果不是*
	if edition != "*" {
		parts = append(parts, ":", escapeCpe22Value(edition))
	} else if language != "*" ||
		cpe.SoftwareEdition != "" || cpe.TargetSoftware != "" ||
		cpe.TargetHardware != "" || cpe.Other != "" {
		parts = append(parts, ":")
	}

	// 添加Language如果不是*
	if language != "*" {
		parts = append(parts, ":", escapeCpe22Value(language))
	} else if cpe.SoftwareEdition != "" || cpe.TargetSoftware != "" ||
		cpe.TargetHardware != "" || cpe.Other != "" {
		parts = append(parts, ":")
	}

	// 添加扩展字段
	if cpe.SoftwareEdition != "" || cpe.TargetSoftware != "" ||
		cpe.TargetHardware != "" || cpe.Other != "" {

		parts = append(parts, ":~")

		if cpe.SoftwareEdition != "" {
			parts = append(parts, escapeCpe22Value(cpe.SoftwareEdition))
		}

		parts = append(parts, "~")

		if cpe.TargetSoftware != "" {
			parts = append(parts, escapeCpe22Value(cpe.TargetSoftware))
		}

		parts = append(parts, "~")

		if cpe.TargetHardware != "" {
			parts = append(parts, escapeCpe22Value(cpe.TargetHardware))
		}

		parts = append(parts, "~")

		if cpe.Other != "" {
			parts = append(parts, escapeCpe22Value(cpe.Other))
		}
	}

	return strings.Join(parts, "")
}

/**
 * convertCpe22ToCpe23 将CPE 2.2格式转换为CPE 2.3格式
 *
 * 此函数实现了CPE 2.2格式字符串到CPE 2.3格式字符串的转换，按照官方标准进行映射。
 * 处理了基本格式和扩展格式（带波浪线的格式）的转换，转义和反转义特殊字符。
 *
 * @param cpe22 string CPE 2.2格式的字符串，以"cpe:/"开头
 * @return string 转换后的CPE 2.3格式字符串，如果输入无效则返回空字符串
 *
 * 注意事项：
 *   - 如果输入格式不正确（不以"cpe:/"开头），返回空字符串
 *   - 函数会自动处理各个字段的转义和反转义
 *   - 转换遵循官方CPE规范中定义的2.2到2.3的映射规则
 *
 * 示例:
 *   ```go
 *   // 基本格式转换
 *   cpe23 := cpe.convertCpe22ToCpe23("cpe:/a:apache:tomcat:8.5.0")
 *   fmt.Println(cpe23)
 *   // 输出: cpe:2.3:a:apache:tomcat:8.5.0:*:*:*:*:*:*:*
 *
 *   // 扩展格式转换
 *   cpe23 := cpe.convertCpe22ToCpe23("cpe:/a:mysql:mysql:5.7.12:::~~~enterprise~")
 *   fmt.Println(cpe23)
 *   // 输出: cpe:2.3:a:mysql:mysql:5.7.12:*:*:*:enterprise:*:*:*
 *
 *   // 带特殊字符的转换
 *   cpe23 := cpe.convertCpe22ToCpe23("cpe:/a:some\\.vendor:product\\/name:1\\.0")
 *   fmt.Println(cpe23)
 *   // 输出: cpe:2.3:a:some\.vendor:product\/name:1\.0:*:*:*:*:*:*:*
 *   ```
 *
 * @see ParseCpe22 用于解析CPE 2.2字符串为CPE结构体
 * @see FormatCpe23 用于生成CPE 2.3格式字符串
 */
func convertCpe22ToCpe23(cpe22 string) string {
	// 检查输入
	if !strings.HasPrefix(cpe22, "cpe:/") {
		return ""
	}

	// 去掉前缀
	content := strings.TrimPrefix(cpe22, "cpe:/")

	// 分割成不同的部分
	parts := strings.Split(content, ":")

	// 至少需要有part部分
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}

	// 准备CPE 2.3部分
	cpe23Parts := []string{"cpe", "2.3"}

	// 添加part
	part := parts[0]
	firstColonIdx := strings.Index(part, ":")
	var partValue string
	if firstColonIdx != -1 {
		partValue = part[:1] // 取第一个字符作为part
		parts[0] = part[1:]  // 剩余部分作为第一个字段的值
	} else {
		partValue = part
		parts = parts[1:] // 剩余部分
	}
	cpe23Parts = append(cpe23Parts, escapeValue(partValue))

	// 处理扩展部分
	var extParts []string

	// 检查是否有扩展部分
	for i, p := range parts {
		if strings.Contains(p, "~") {
			extIdx := strings.Index(p, "~")
			if extIdx > 0 {
				// 分号前有值
				parts[i] = p[:extIdx]
				extParts = strings.Split(p[extIdx:], "~")
			} else {
				// 分号在开头
				parts[i] = ""
				extParts = strings.Split(p, "~")
			}
			// 移除第一个空元素
			if len(extParts) > 0 && extParts[0] == "" {
				extParts = extParts[1:]
			}
			break
		}
	}

	// 标准部分 (vendor, product, version, update, edition, language)
	// 添加vendor
	if len(parts) > 0 && parts[0] != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(parts[0])))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加product
	if len(parts) > 1 && parts[1] != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(parts[1])))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加version
	if len(parts) > 2 && parts[2] != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(parts[2])))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加update
	var updateValue string
	if len(parts) > 3 && parts[3] != "" {
		updateValue = parts[3]
	}
	if updateValue != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(updateValue)))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加edition
	var editionValue string
	if len(parts) > 4 && parts[4] != "" {
		editionValue = parts[4]
	}
	if editionValue != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(editionValue)))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加language
	var languageValue string
	if len(parts) > 5 && parts[5] != "" {
		languageValue = parts[5]
	}
	if languageValue != "" {
		cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(languageValue)))
	} else {
		cpe23Parts = append(cpe23Parts, "*")
	}

	// 添加其他扩展字段
	if len(extParts) > 0 {
		// 添加swEdition
		if len(extParts) > 0 && extParts[0] != "" {
			cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(extParts[0])))
		} else {
			cpe23Parts = append(cpe23Parts, "*")
		}

		// 添加targetSw
		if len(extParts) > 1 && extParts[1] != "" {
			cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(extParts[1])))
		} else {
			cpe23Parts = append(cpe23Parts, "*")
		}

		// 添加targetHw
		if len(extParts) > 2 && extParts[2] != "" {
			cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(extParts[2])))
		} else {
			cpe23Parts = append(cpe23Parts, "*")
		}

		// 添加other
		if len(extParts) > 3 && extParts[3] != "" {
			cpe23Parts = append(cpe23Parts, escapeValue(unescapeCpe22Value(extParts[3])))
		} else {
			cpe23Parts = append(cpe23Parts, "*")
		}
	} else {
		// 如果没有扩展部分，添加四个通配符
		cpe23Parts = append(cpe23Parts, "*", "*", "*", "*")
	}

	return strings.Join(cpe23Parts, ":")
}

/**
 * escapeCpe22Value 对CPE 2.2格式的值进行转义
 *
 * 将字符串中的特殊字符按照CPE 2.2规范进行转义，以便在CPE 2.2格式字符串中正确表示。
 * 特殊字符包括冒号(:)、斜杠(/)、波浪线(~)和点(.)，但版本号字段中的点不进行转义。
 *
 * @param value string 需要转义的原始字符串
 * @return string 转义后的字符串
 *
 * 转义规则：
 *   - 反斜杠(\)转义为\\
 *   - 冒号(:)转义为%3a
 *   - 斜杠(/)转义为%2f
 *   - 波浪线(~)转义为%7e
 *   - 点(.)转义为%2e（仅在非版本字段中）
 *   - "*"和"-"等特殊值不进行转义
 *
 * 注意事项：
 *   - 如果value是特殊通配符("*"或"-")或空字符串，则直接返回
 *   - 对于版本字段，会检测字符串格式判断是否为版本号（如1.2.3格式），版本号中的点不会被转义
 *   - 线程安全：此函数不修改输入参数，可并发调用
 *
 * 示例:
 *   ```go
 *   // 基本转义
 *   escaped := cpe.escapeCpe22Value("product:name")
 *   fmt.Println(escaped) // 输出: product%3aname
 *
 *   // 版本字段中的点不转义
 *   escaped := cpe.escapeCpe22Value("1.2.3")
 *   fmt.Println(escaped) // 输出: 1.2.3 (不转义点)
 *
 *   // 多种特殊字符转义
 *   escaped := cpe.escapeCpe22Value("name/with~special:chars.here")
 *   fmt.Println(escaped) // 输出: name%2fwith%7especial%3achars%2ehere
 *   ```
 *
 * @see unescapeCpe22Value 用于将转义后的CPE 2.2字符串还原
 */
func escapeCpe22Value(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 检查是否是版本字段
	isVersion := false
	if regexp.MustCompile(`^\d+(\.\d+)+$`).MatchString(value) {
		isVersion = true
	}

	// 创建复制版本避免直接修改原值
	escaped := value

	// 转义特殊字符
	escaped = strings.ReplaceAll(escaped, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, ":", "%3a")
	escaped = strings.ReplaceAll(escaped, "/", "%2f")
	escaped = strings.ReplaceAll(escaped, "~", "%7e")

	// 只在非版本字段中转义点
	if !isVersion {
		escaped = strings.ReplaceAll(escaped, ".", "%2e")
	}

	return escaped
}

/**
 * unescapeCpe22Value 对CPE 2.2格式的值进行反转义
 *
 * 将CPE 2.2格式字符串中转义的特殊字符还原为普通字符。
 * 处理包括%3a (冒号)、%2f (斜杠)、%7e (波浪线)、%2e (点)等转义序列。
 *
 * @param value string 包含转义字符的CPE 2.2字符串值
 * @return string 反转义后的原始字符串
 *
 * 反转义规则：
 *   - %3a 转换为 :
 *   - %2f 转换为 /
 *   - %7e 转换为 ~
 *   - %2e 转换为 .
 *   - \\\\ 转换为 \\
 *   - "*"和"-"等特殊值不进行处理
 *
 * 注意事项：
 *   - 如果value是特殊通配符("*"或"-")或空字符串，则直接返回
 *   - 线程安全：此函数不修改输入参数，可并发调用
 *
 * 示例:
 *   ```go
 *   // 基本反转义
 *   unescaped := cpe.unescapeCpe22Value("product%3aname")
 *   fmt.Println(unescaped) // 输出: product:name
 *
 *   // 多种特殊字符反转义
 *   unescaped := cpe.unescapeCpe22Value("name%2fwith%7especial%3achars%2ehere")
 *   fmt.Println(unescaped) // 输出: name/with~special:chars.here
 *
 *   // 不包含转义字符的值
 *   unescaped := cpe.unescapeCpe22Value("normal_text")
 *   fmt.Println(unescaped) // 输出: normal_text (保持不变)
 *   ```
 *
 * @see escapeCpe22Value 用于将字符串转义为CPE 2.2格式
 */
func unescapeCpe22Value(value string) string {
	if value == "*" || value == "-" || value == "" {
		return value
	}

	// 替换特殊字符
	replacer := strings.NewReplacer(
		"%3a", ":",
		"%2f", "/",
		"%7e", "~",
		"%2e", ".", // 添加对点的反转义
		"\\\\", "\\",
	)

	return replacer.Replace(value)
}

// cpe:/a:baidu_tongji_generator_project:baidu_tongji_generator:::~~~wordpress~~
