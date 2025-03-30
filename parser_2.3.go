package cpe

import (
	"strings"
)

const CPE23Header = "cpe"
const CPE23Version = "2.3"

/**
 * ParseCpe23 解析CPE 2.3字符串格式并转换为CPE结构体
 *
 * CPE 2.3是一种标准化的产品命名方式，用于唯一标识IT产品、系统和服务。
 * 格式为：cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
 *
 * @param cpe23 CPE 2.3格式的字符串，例如 "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
 * @return (*CPE, error) 成功时返回解析后的CPE结构体指针，失败时返回nil和错误
 *
 * @error 当输入字符串格式不符合CPE 2.3标准时，返回InvalidFormatError
 * @error 当part字段值不是a、h、o或*时，返回InvalidPartError
 *
 * 示例:
 *   ```go
 *   // 解析Windows 10的CPE
 *   winCPE, err := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   if err != nil {
 *       log.Fatalf("解析CPE失败: %v", err)
 *   }
 *   fmt.Printf("厂商: %s, 产品: %s, 版本: %s\n", winCPE.Vendor, winCPE.ProductName, winCPE.Version)
 *   // 输出: 厂商: microsoft, 产品: windows, 版本: 10
 *
 *   // 解析Adobe Reader的CPE
 *   adobeCPE, err := cpe.ParseCpe23("cpe:2.3:a:adobe:reader:2021.001.20150:*:*:*:*:*:*:*")
 *   if err != nil {
 *       log.Fatalf("解析CPE失败: %v", err)
 *   }
 *   ```
 */
func ParseCpe23(cpe23 string) (*CPE, error) {
	split := strings.Split(cpe23, ":")
	if len(split) != 13 {
		return nil, NewInvalidFormatError(cpe23)
	}

	// 文件头检查
	if strings.ToLower(split[0]) != CPE23Header {
		return nil, NewInvalidFormatError(cpe23)
	}
	// 版本检查
	if split[1] != CPE23Version {
		return nil, NewInvalidFormatError(cpe23)
	}

	// 检查Part有效性
	part := split[2]
	if part != "a" && part != "h" && part != "o" && part != "*" {
		return nil, NewInvalidPartError(part)
	}

	// 创建CPE结构体
	cpe := &CPE{
		Cpe23: cpe23,
	}

	// 设置Part
	switch part {
	case "a":
		cpe.Part = *PartApplication
	case "h":
		cpe.Part = *PartHardware
	case "o":
		cpe.Part = *PartOperationSystem
	}

	// 设置其他属性
	cpe.Vendor = Vendor(unescapeValue(split[3]))
	cpe.ProductName = Product(unescapeValue(split[4]))
	cpe.Version = Version(unescapeValue(split[5]))
	cpe.Update = Update(unescapeValue(split[6]))
	cpe.Edition = Edition(unescapeValue(split[7]))
	cpe.Language = Language(unescapeValue(split[8]))
	cpe.SoftwareEdition = unescapeValue(split[9])
	cpe.TargetSoftware = unescapeValue(split[10])
	cpe.TargetHardware = unescapeValue(split[11])
	cpe.Other = unescapeValue(split[12])

	return cpe, nil
}

// FormatCpe23 将CPE对象格式化为CPE 2.3字符串
func FormatCpe23(cpe *CPE) string {
	if cpe.Cpe23 != "" {
		return cpe.Cpe23
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

	// 对于版本号，我们需要特殊处理，不要转义点
	// 我们会在后面的escapeValue中处理其他特殊字符

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

	softwareEdition := cpe.SoftwareEdition
	if softwareEdition == "" {
		softwareEdition = "*"
	}

	targetSoftware := cpe.TargetSoftware
	if targetSoftware == "" {
		targetSoftware = "*"
	}

	targetHardware := cpe.TargetHardware
	if targetHardware == "" {
		targetHardware = "*"
	}

	other := cpe.Other
	if other == "" {
		other = "*"
	}

	// 构建CPE 2.3字符串
	parts := []string{
		"cpe", "2.3",
		partShortName,
		escapeValue(vendor),
		escapeValue(productName),
		escapeValue(version), // 使用escapeValue而不是特殊处理
		escapeValue(update),
		escapeValue(edition),
		escapeValue(language),
		escapeValue(softwareEdition),
		escapeValue(targetSoftware),
		escapeValue(targetHardware),
		escapeValue(other),
	}

	return strings.Join(parts, ":")
}

// cpe:/a:baidu_tongji_generator_project:baidu_tongji_generator:::~~~wordpress~~
