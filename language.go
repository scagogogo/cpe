package cpe

/**
 * Language 表示CPE中的语言组件
 *
 * 在CPE规范中，Language用于标识软件的语言版本。通常使用ISO 639-2标准的语言代码：
 * 例如"zh"(中文)、"en"(英文)、"fr"(法语)等。Language也可以使用特殊值"*"(任意语言)
 * 或"-"(不适用)。
 *
 * Language字段对于区分同一软件的不同语言版本非常重要，因为不同语言版本可能具有
 * 不同的安全漏洞或兼容性问题。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示中文版Microsoft Office的CPE
 *   officeZhCPE := &cpe.CPE{
 *       Part:        *cpe.PartApplication,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("office"),
 *       Version:     cpe.Version("2019"),
 *       Language:    cpe.Language("zh"),
 *   }
 *
 *   // 使用特殊值匹配任意语言版本
 *   officeAnyCPE := &cpe.CPE{
 *       Part:        *cpe.PartApplication,
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("office"),
 *       Language:    cpe.Language("*"),  // 匹配任意语言
 *   }
 *
 *   // 创建搜索条件，查找特定语言的产品
 *   searchCriteria := &cpe.CPE{
 *       Language: cpe.Language("ja"),  // 查找日语版本
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   results := cpe.Search(cpeList, searchCriteria, options)
 *   ```
 */
type Language string
