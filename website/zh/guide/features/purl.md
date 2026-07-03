---
title: PURL 与生态系统
outline: deep
---

# 🔗 PURL 与生态系统

**Package URL（PURL）** 是跨生态的包规范标识符（`pkg:maven/...`、`pkg:npm/...`、`pkg:golang/...`）。`cpeskills` 解析 PURL、映射到生态系统，并在 PURL 与 CPE 之间双向转换——把 NVD 世界（CPE）与包管理器世界（PURL）桥接起来。

## 概念

转换是有损的：CPE 携带 vendor + product + version，而 PURL 携带 type + namespace + name + version。库为每次转换返回一个**置信度评分**（0.0–1.0），让你知道映射何时不确定。

```mermaid
flowchart LR
    C["CPE"] -->|"CPEToPURL<br/>(purl, confidence, err)"| P["PackageURL"]
    P -->|"PURLToCPE<br/>(cpe, confidence, err)"| C
    P -->|"Ecosystem()"| E["Ecosystem<br/>（Maven/NPM/Go/...）"]
    R["原始 PURL 字符串"] -->|"ParsePURL"| P
    N["type/ns/name/ver"|] -->|"NewPURL"| P
```

## 解析、构建与查询

```go
package main

import (
    "fmt"

    cpeskills "github.com/scagogogo/cpe-skills"
)

func main() {
    purl, err := cpeskills.ParsePURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0")
    if err != nil {
        panic(err)
    }
    fmt.Printf("生态系统=%s\n", purl.Ecosystem())

    built := cpeskills.NewPURL("npm", "", "lodash", "4.17.21")
    fmt.Println(built.String())
}
```

## 在 CPE 与 PURL 之间互转

```go
cpe := cpeskills.MustParse("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")

purl, conf, err := cpeskills.CPEToPURL(cpe)
if err == nil && conf > 0.5 {
    fmt.Printf("映射到 %s（置信度 %.2f）\n", purl.String(), conf)
}

back, conf2, err := cpeskills.PURLToCPE(purl)
if err == nil {
    fmt.Printf("转回 CPE %s（置信度 %.2f）\n", back.String(), conf2)
}
```

## 最佳实践

- **检查置信度评分** —— 低于约 0.5 时 vendor/product 推断不可靠，宜保留原标识符。
- **在 SBOM 组件上同时存 CPE 与 PURL**（`SetCPE` + `SetPURL`），让丰富化与生态工具各取所需。
- **用 `Ecosystem()` 分发逻辑**（如 Maven 与 Go 的修复库查询），而非字符串匹配 PURL type。

## 相关模块

- [SBOM](./sbom.md) —— `SetCPE` / `SetPURL` 为组件附加两个标识符。
- [清单转 SBOM](./manifest.md) —— 清单解析器按生态为每个组件产出 PURL。
- [基础解析](../basic-parsing.md) —— 喂给 `CPEToPURL` 的 CPE 解析。
