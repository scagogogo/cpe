package cpe

/**
 * Vendor 表示CPE中的产品供应商
 *
 * 在CPE规范中，Vendor是指产品的制造商或提供者的名称。供应商名称通常是小写字母，
 * 多词名称使用下划线连接，如"microsoft"、"adobe"、"apache_software_foundation"等。
 * 供应商也可以使用特殊值"*"(任意供应商)或"-"(不适用)。
 *
 * 在CPE标准化过程中，供应商名称会被转换为小写，空格会被替换为下划线。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Microsoft产品的CPE
 *   microsoftCPE := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *   }
 *
 *   // 在搜索条件中使用特定供应商
 *   searchCriteria := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   results := cpe.Search(cpeList, searchCriteria, options)
 *
 *   // 使用标准化函数处理供应商名称
 *   normalizedVendor := cpe.NormalizeComponent("Microsoft Corporation")
 *   // 结果为 "microsoft_corporation"
 *   ```
 */
type Vendor string
