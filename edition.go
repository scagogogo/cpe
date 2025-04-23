package cpe

/**
 * Edition 表示CPE中的版本类型组件
 *
 * 在CPE规范中，Edition表示产品的版本类型或发行类型，如"SP1"(Service Pack 1)、
 * "企业版"、"专业版"等。Edition也可以使用特殊值"*"(任意版本类型)或"-"(不适用)。
 *
 * 版本类型与具体版本号(Version)不同，它描述的是产品的发行类型而非版本号。
 * 在CPE 2.3规范中，Edition字段部分功能已被更精细的SoftwareEdition字段取代，
 * 但为了向后兼容仍然保留。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Windows 10专业版的CPE
 *   win10ProCPE := &cpe.CPE{
 *       Part:        *cpe.PartOperationSystem,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *       Edition:     cpe.Edition("pro"),
 *   }
 *
 *   // 使用通配符匹配任意版本类型
 *   windowsAnyCPE := &cpe.CPE{
 *       Part:        *cpe.PartOperationSystem,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Edition:     cpe.Edition("*"),  // 匹配任意版本类型
 *   }
 *
 *   // 创建搜索条件，查找特定版本类型的产品
 *   searchCriteria := &cpe.CPE{
 *       Edition: cpe.Edition("enterprise"),
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   results := cpe.Search(cpeList, searchCriteria, options)
 *   ```
 */
type Edition string
