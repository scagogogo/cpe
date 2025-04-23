package cpe

/**
 * Update 表示CPE中产品的更新标识符
 *
 * 在CPE规范中，Update表示特定版本的更新或补丁级别，如"sp1"（Service Pack 1）、
 * "update2"、"patch3"等。Update也可以使用特殊值"*"(任意更新)或"-"(不适用)。
 *
 * 与其他CPE组件类似，更新标识符在标准化过程中会被转换为小写，空格会被替换为下划线。
 *
 * 示例:
 *   ```go
 *   // 创建一个表示Windows 10 SP1的CPE
 *   windowsCPE := &cpe.CPE{
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *       Update:      cpe.Update("sp1"),
 *   }
 *
 *   // 搜索具有特定更新的产品
 *   searchCriteria := &cpe.CPE{
 *       ProductName: cpe.Product("windows"),
 *       Update:      cpe.Update("sp1"),
 *   }
 *   options := cpe.DefaultMatchOptions()
 *   results := cpe.Search(cpeList, searchCriteria, options)
 *
 *   // 使用正则表达式匹配更新
 *   options.UseRegex = true
 *   regexCriteria := &cpe.CPE{
 *       Update: cpe.Update("sp[0-9]"),  // 匹配sp后跟随一个数字
 *   }
 *   ```
 */
type Update string
