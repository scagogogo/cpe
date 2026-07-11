package cpeskills

/**
 * Product 表示CPE中的产品名称组件
 *
 * 在CPE规范中，Product表示软件或硬件的具体产品名称，如"windows"、"office"、
 * "iphone"等。Product也可以使用特殊值"*"(任意产品)或"-"(不适用)。
 *
 * 与其他CPE组件类似，产品名称在标准化过程中会被转换为小写，空格会被替换为下划线。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Microsoft Office产品的CPE
 *   officeCPE := &cpeskills.CPE{
 *       Vendor:      cpeskills.Vendor("microsoft"),
 *       ProductName: cpeskills.Product("office"),
 *       Version:     cpeskills.Version("2019"),
 *   }
 *
 *   // 搜索特定产品
 *   searchCriteria := &cpeskills.CPE{
 *       ProductName: cpeskills.Product("office"),
 *   }
 *   options := cpeskills.DefaultMatchOptions()
 *   results := cpeskills.Search(cpeList, searchCriteria, options)
 *
 *   // 使用正则表达式匹配产品名
 *   options.UseRegex = true
 *   regexCriteria := &cpeskills.CPE{
 *       ProductName: cpeskills.Product("(word|excel|powerpoint)"),
 *   }
 *   ```
 */
type Product string
