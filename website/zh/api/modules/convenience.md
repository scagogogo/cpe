---
title: Convenience Functions
outline: deep
---

# 🛠️ 便捷函数

本模块提供一组包级便捷函数，简化 CPE 的解析、校验、匹配、转换与过滤等常见操作。

## 🚀 MustParse

```go
func MustParse(cpeStr string) *CPE
```

解析 CPE 字符串，解析失败时 panic。适用于初始化常量或测试代码。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpeStr` | `string` | CPE 字符串 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `*CPE` | 解析得到的 CPE 对象 |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
```

## 🔁 ParseOr

```go
func ParseOr(cpeStr string, defaultCPE *CPE) *CPE
```

解析 CPE 字符串，失败时返回 `defaultCPE` 而不报错。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpeStr` | `string` | CPE 字符串 |
| `defaultCPE` | `*CPE` | 解析失败时使用的默认值 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `*CPE` | 解析结果或默认值 |

```go
cpe := cpeskills.ParseOr("bad-string", cpeskills.MustParse("cpe:2.3:a:*:*:*:*:*:*:*:*:*"))
```

## ✅ IsCPE23String

```go
func IsCPE23String(s string) bool
```

判断字符串是否符合 CPE 2.3 格式。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `s` | `string` | 待判断的字符串 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `bool` | 是 2.3 格式返回 `true` |

```go
fmt.Println(cpeskills.IsCPE23String("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"))
```

## ✅ IsCPE22String

```go
func IsCPE22String(s string) bool
```

判断字符串是否符合 CPE 2.2 格式。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `s` | `string` | 待判断的字符串 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `bool` | 是 2.2 格式返回 `true` |

```go
fmt.Println(cpeskills.IsCPE22String("cpe:/a:microsoft:windows:10"))
```

## ⚡ QuickMatch

```go
func QuickMatch(cpeStr1, cpeStr2 string) (bool, error)
```

快速匹配两个 CPE 字符串，无需手动解析。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpeStr1` | `string` | 第一个 CPE 字符串 |
| `cpeStr2` | `string` | 第二个 CPE 字符串 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `bool` | 匹配返回 `true` |
| 第 2 个 | `error` | 解析失败时返回错误 |

```go
ok, err := cpeskills.QuickMatch(
    "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
)
```

## 🏷️ StringToPart

```go
func StringToPart(s string) (*Part, error)
```

将字符串转换为 `Part` 类型。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `s` | `string` | 组件类型字符串（如 `a`/`o`/`h`） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `*Part` | 转换结果 |
| 第 2 个 | `error` | 非法值时返回错误 |

```go
part, err := cpeskills.StringToPart("a")
```

## 📝 FormatCPE

```go
func FormatCPE(cpe *CPE, version string) (string, error)
```

按指定 CPE 版本（`"2.2"` 或 `"2.3"`）格式化 CPE 对象。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpe` | `*CPE` | 待格式化的 CPE 对象 |
| `version` | `string` | 目标版本 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `string` | 格式化结果 |
| 第 2 个 | `error` | 版本非法时返回错误 |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
s, _ := cpeskills.FormatCPE(cpe, "2.2")
```

## 🧬 Clone

```go
func Clone(cpe *CPE) *CPE
```

深拷贝一个 CPE 对象。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpe` | `*CPE` | 被克隆的 CPE 对象 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `*CPE` | 克隆得到的新对象 |

```go
cpe := cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
clone := cpeskills.Clone(cpe)
```

## 🔁 CPEsToStrings

```go
func CPEsToStrings(cpes []*CPE) []string
```

将 CPE 切片转换为字符串切片（按 2.3 URI 格式化）。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpes` | `[]*CPE` | CPE 对象切片 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]string` | URI 字符串切片 |

```go
cpes := []*CPE{cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")}
strs := cpeskills.CPEsToStrings(cpes)
```

## 🔁 StringsToCPEs

```go
func StringsToCPEs(strs []string) []*CPE
```

将字符串切片转换为 CPE 切片。无法解析的条目会被跳过。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `strs` | `[]string` | CPE 字符串切片 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]*CPE` | 解析得到的 CPE 切片 |

```go
cpes := cpeskills.StringsToCPEs([]string{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"})
```

## 🔎 FilterByPart

```go
func FilterByPart(cpes []*CPE, part *Part) []*CPE
```

按组件类型过滤 CPE 列表。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpes` | `[]*CPE` | 待过滤的 CPE 列表 |
| `part` | `*Part` | 目标组件类型 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]*CPE` | 匹配的子集 |

```go
part, _ := cpeskills.StringToPart("a")
apps := cpeskills.FilterByPart(cpes, part)
```

## 🔎 FilterByVendor

```go
func FilterByVendor(cpes []*CPE, vendor string) []*CPE
```

按供应商过滤 CPE 列表。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpes` | `[]*CPE` | 待过滤的 CPE 列表 |
| `vendor` | `string` | 目标供应商 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]*CPE` | 匹配的子集 |

```go
ms := cpeskills.FilterByVendor(cpes, "microsoft")
```

## 🔎 FilterByProduct

```go
func FilterByProduct(cpes []*CPE, product string) []*CPE
```

按产品名过滤 CPE 列表。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpes` | `[]*CPE` | 待过滤的 CPE 列表 |
| `product` | `string` | 目标产品名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `[]*CPE` | 匹配的子集 |

```go
wins := cpeskills.FilterByProduct(cpes, "windows")
```

## 🏷️ GetPartName

```go
func GetPartName(shortName string) string
```

将组件类型的短名（`a`/`o`/`h`）转换为完整名称。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `shortName` | `string` | 短名 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| 第 1 个 | `string` | 完整名称 |

```go
fmt.Println(cpeskills.GetPartName("a")) // application
```

## 🧭 便捷函数关系

```mermaid
flowchart TD
    S[CPE 字符串] --> MP[MustParse]
    S --> PO[ParseOr]
    S --> I23[IsCPE23String]
    S --> I22[IsCPE22String]
    S --> QM[QuickMatch]
    S --> STP[StringToPart]
    C[CPE 对象] --> FC[FormatCPE]
    C --> CL[Clone]
    CS[[]CPE] --> C2S[CPEsToStrings]
    SS[[]string] --> S2C[StringsToCPEs]
    CS --> FBP[FilterByPart]
    CS --> FBV[FilterByVendor]
    CS --> FBP2[FilterByProduct]
    style S fill:#fff3e0,stroke:#ef6c00
    style C fill:#e8f5e9,stroke:#2e7d32
```
