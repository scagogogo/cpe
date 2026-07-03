---
title: Dictionary
outline: deep
---

# 📚 CPE 字典

`dictionary` 模块建模 NVD CPE 字典：`CPEDictionary` 持有 `CPEItem` 条目列表，每个条目封装一个 `CPE` 及人类可读的元数据（标题、参考链接、弃用状态）。该模块解析官方 NVD XML 字典并重新导出，同时提供内存查询与变更辅助方法。

## 类型：CPEDictionary

```go
type CPEDictionary struct {
    Items         []*CPEItem `json:"items" bson:"items"`           // CPE 条目列表
    GeneratedAt   time.Time  `json:"generated_at" bson:"generated_at"` // 字典生成时间
    SchemaVersion string     `json:"schema_version" bson:"schema_version"` // CPE 规范版本
}
```

`CPEDictionary` 是顶层容器。`Items` 为权威列表；`GeneratedAt` 和 `SchemaVersion` 携带来自源 XML 的来源信息。

## 类型：CPEItem

```go
type CPEItem struct {
    Name            string     `json:"name" xml:"name" bson:"name"`                 // 标准 CPE 名称（2.3 形式）
    Title           string     `json:"title" xml:"title" bson:"title"`              // 人类可读标题
    References      []Reference `json:"references" xml:"references>reference" bson:"references"` // 参考链接
    Deprecated      bool       `json:"deprecated" xml:"deprecated,attr" bson:"deprecated"` // 是否已弃用
    DeprecationDate *time.Time `json:"deprecation_date" xml:"deprecation_date" bson:"deprecation_date"` // 弃用日期
    CPE             *CPE       `json:"cpe" bson:"cpe"`                               // 解析后的 CPE 对象
}
```

`CPEItem` 表示单个字典条目。`CPE` 是 `Name` 的解析形式（由 `ParseDictionary` 填充）；若名称无法解析则为 `nil`。

## 类型：Reference

```go
type Reference struct {
    URL  string `json:"url" xml:"href,attr" bson:"url"`  // 参考 URL
    Type string `json:"type" xml:"type" bson:"type"`     // 引用类型，如 "Vendor"、"Advisory"
}
```

`Reference` 是附加到 `CPEItem` 的单个外部链接。

## 📖 ParseDictionary

```go
func ParseDictionary(r io.Reader) (*CPEDictionary, error)
```

从 `r` 解码 NVD CPE 字典 XML 流，将每个 `<cpe-item>` 转换为 `CPEItem`。每项的 `Name` 被解析（2.3 或 2.2）为 `CPE`；`Deprecated`/`DeprecationDate` 和 `References` 从 XML 属性/子元素填充。`GeneratedAt` 在存在时按 RFC3339 解析。失败时返回包装 XML 解码错误的 `OperationFailedError`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `r` | `io.Reader` | XML 数据流 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CPEDictionary` | 解析得到的字典 |
| #2 | `error` | XML 解码失败时非 `nil`（已包装） |

```go
file, _ := os.Open("official-cpe-dictionary_v2.3.xml")
defer file.Close()
dict, err := cpeskills.ParseDictionary(file)
if err != nil {
    log.Fatalf("parse: %v", err)
}
fmt.Printf("%d items\n", len(dict.Items))
```

## 📤 ExportDictionary

```go
func ExportDictionary(dict *CPEDictionary, w io.Writer) error
```

将 `dict` 序列化为 NVD CPE 字典 XML，向 `w` 写入 XML 头部和缩进的 `<cpe-list>`。失败时返回包装底层 I/O 或编码错误的 `OperationFailedError`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `dict` | `*CPEDictionary` | 要导出的字典 |
| `w` | `io.Writer` | XML 输出目标 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `error` | 写入/编码失败时非 `nil`（已包装） |

```go
var buf bytes.Buffer
if err := cpeskills.ExportDictionary(dict, &buf); err != nil {
    log.Fatalf("export: %v", err)
}
```

## 🔍 FindItemByName

```go
func (d *CPEDictionary) FindItemByName(name string) *CPEItem
```

返回第一个 `Name` 等于 `name` 的条目，无则返回 `nil`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEDictionary` | 字典 |
| `name` | `string` | 要查找的 CPE 名称（2.3 形式） |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CPEItem` | 匹配的条目，或 `nil` |

```go
item := dict.FindItemByName("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
```

## 🔍 FindItemsByCriteria

```go
func (d *CPEDictionary) FindItemsByCriteria(criteria *CPE, options *MatchOptions) []*CPEItem
```

返回所有已解析 `CPE` 在 `options` 下匹配 `criteria` 的条目（通过包内部 `matchCPE`）。`CPE` 为 `nil` 的条目被跳过。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEDictionary` | 字典 |
| `criteria` | `*CPE` | 匹配条件 |
| `options` | `*MatchOptions` | 匹配选项 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `[]*CPEItem` | 匹配的条目（无则空/`nil`） |

```go
items := dict.FindItemsByCriteria(&cpeskills.CPE{
    Vendor: cpeskills.Vendor("apache"),
}, &cpeskills.MatchOptions{IgnoreVersion: true})
```

## ➕ AddItem

```go
func (d *CPEDictionary) AddItem(item *CPEItem)
```

将 `item` 加入字典。若已存在同名条目，则就地替换；否则追加。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEDictionary` | 字典 |
| `item` | `*CPEItem` | 要添加的条目 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| （无） | | |

```go
dict.AddItem(cpeskills.NewCPEItem(cpe, "Apache Log4j 2.0"))
```

## ➖ RemoveItem

```go
func (d *CPEDictionary) RemoveItem(name string) bool
```

移除 `Name` 等于 `name` 的条目。移除了返回 `true`，否则返回 `false`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| 接收者 | `*CPEDictionary` | 字典 |
| `name` | `string` | 要移除的 CPE 名称 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `bool` | 移除成功为 `true` |

```go
if dict.RemoveItem("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*") {
    fmt.Println("removed")
}
```

## 🆕 NewCPEItem

```go
func NewCPEItem(cpe *CPE, title string) *CPEItem
```

从 `cpe` 和 `title` 创建 `CPEItem`。`cpe.Cpe23` 非空时 `Name` 设为它，否则设为 `FormatCpe23(cpe)`。`CPE` 设为 `cpe`。

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cpe` | `*CPE` | CPE |
| `title` | `string` | 人类可读标题 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| #1 | `*CPEItem` | 新的字典条目 |

```go
item := cpeskills.NewCPEItem(cpe, "Apache Log4j 2.0")
dict.AddItem(item)
```

## 🧭 Dictionary 解析与查询流

```mermaid
flowchart TD
    XML[NVD XML 流] --> PD[ParseDictionary]
    PD --> DICT[CPEDictionary]
    DICT --> ITEMS[Items []*CPEItem]
    ITEMS --> NAME[Name]
    ITEMS --> TITLE[Title]
    ITEMS --> REF[References]
    ITEMS --> CPE[CPE 已解析]
    PC[ParseCpe23/22] -. 填充 .-> CPE
    ED[ExportDictionary] --> OUT[XML 输出]
    DICT --> ED
    FIN[FindItemByName] --> ITEMS
    FIC[FindItemsByCriteria] --> matchCPE
    matchCPE --> CPE
    AI[AddItem] --> ITEMS
    RI[RemoveItem] --> ITEMS
    NCI[NewCPEItem] --> AI
    style PD fill:#e8f5e9,stroke:#2e7d32
    style ED fill:#e3f2fd,stroke:#1565c0
    style FIN fill:#fff3e0,stroke:#ef6c00
```
