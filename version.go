package cpe

/**
 * Version 表示CPE中产品的版本号
 *
 * 在CPE规范中，Version是表示产品版本的字符串，可以包含数字、字母和特殊字符。
 * 版本号可以是具体的数值如"10.0.1"，也可以使用特殊值"*"(任意版本)或"-"(不适用)。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Windows 10的CPE
 *   windowsCPE := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *   }
 *
 *   // 版本比较示例
 *   v1 := cpe.Version("10.0")
 *   v2 := cpe.Version("11.0")
 *   result := cpe.compareVersionsSimple(string(v1), string(v2)) // 返回 -1，表示v1 < v2
 *
 *   // 在匹配选项中设置版本范围
 *   options := cpe.DefaultMatchOptions()
 *   options.VersionRange = true
 *   options.MinVersion = "10.0"
 *   options.MaxVersion = "11.0"
 *   ```
 */
type Version string
