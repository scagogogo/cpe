---
title: 从 CPE 2.2 迁移到 2.3
outline: deep
---

# 🔄 从 CPE 2.2 迁移到 2.3

CPE 2.2（URI 风格，`cpe:/a:microsoft:windows`）已属遗留。CPE 2.3（格式化字符串，`cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*`）是 NVD 发布格式，也是现代工具链的期望格式。本页说明如何迁移。

## 为何迁移

CPE 2.3 新增了 2.2 无法表达的四个属性字段，是 NVD、SBOM 标准与匹配规范的规范格式。2.2 无法区分同一版本的不同 edition。

| 字段 (2.3)         | 2.2 对应       | 说明                                |
|--------------------|----------------|-------------------------------------|
| `part`             | `part`         | 同                                  |
| `vendor`           | `vendor`       | 同                                  |
| `product`          | `product`      | 同                                  |
| `version`          | `version`      | 同                                  |
| `update`           | `update`       | 同                                  |
| `edition`          | `edition`      | 同                                  |
| `language`         | `language`     | 同                                  |
| `sw_edition`       | —              | **2.3 新增**                        |
| `target_sw`        | —              | **2.3 新增**                        |
| `target_hw`        | —              | **2.3 新增**                        |
| `other`            | —              | **2.3 新增**                        |

2.2 转 2.3 时，四个新字段默认为 `*`（ANY）。

## 通过 Parse + Format 转换

`ParseCpe22` 把 2.2 URI 读入 `CPE` 结构体；`FormatCpe23` 把该结构体写回 2.3 格式化字符串。`CPE` 结构体与格式无关，是天然桥梁。

```go
import "github.com/scagogogo/cpe-skills"

c, err := cpeskills.ParseCpe22("cpe:/a:microsoft:windows:10")
if err != nil {
    log.Fatal(err)
}
fmt.Println(cpeskills.FormatCpe23(c))
// cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
```

`FormatCPE(c, "2.3")` 等价正向，`FormatCPE(c, "2.2")` 反向，目标格式为运行时参数时很方便。

```mermaid
flowchart LR
    A["cpe:/a:vendor:product:1.0"] -->|ParseCpe22| B[CPE 结构体]
    B -->|FormatCpe23| C["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    B -->|FormatCpe22| A
    B -->|FromCPE| D[WFN]
    D -->|ToCPE23String| C
```

## WFN 中间表示

两个解析器最终都构造 **Well-Formed Name**（WFN），两个格式化器都从中读取。`FromCPE` 与 `WFN.ToCPE` 允许直接操作规范形式——在需要先设置仅 2.3 存在的字段、再序列化时很有用。

```go
w := cpeskills.FromCPE(c)            // CPE -> WFN
w.Set(cpeskills.AttrSoftwareEdition, "enterprise")
c2 := w.ToCPE()                      // WFN -> CPE（2.3 字段已填）
fmt.Println(cpeskills.FormatCpe23(c2))
```

参见 [/zh/api/modules/parser-2.2](/zh/api/modules/parser-2.2)、[/zh/api/modules/parser-2.3](/zh/api/modules/parser-2.3) 与 [/zh/api/modules/wfn](/zh/api/modules/wfn)。

## 迁移清单

1. 把任何你可控数据里的 `cpe:/` 字面量替换为 `cpe:2.3:`。
2. 对入站 2.2 数据，入库时 `ParseCpe22` 后 `FormatCpe23`，只存 2.3。
3. 在已知处填充 `sw_edition` / `target_sw` / `target_hw`——能提升匹配精度。
4. 匹配逻辑更新为期望 2.3 字段数（11 个冒号分隔组件）。
5. 遗留字段保留一个版本周期，然后移除。

## 小结

迁移路径：`ParseCpe22` 解析 → 经共享 `CPE`/`WFN` 模型规范化 → `FormatCpe23` 重新输出。2.3 四个新字段默认 ANY，已知应填。解析模块：[/zh/api/modules/parser-2.2](/zh/api/modules/parser-2.2)、[/zh/api/modules/parser-2.3](/zh/api/modules/parser-2.3)；WFN：[/zh/api/modules/wfn](/zh/api/modules/wfn)。
