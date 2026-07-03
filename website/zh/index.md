---
layout: home

title: cpe-skills
titleTemplate: 面向网络安全与 AI Agent 的 CPE 工具包

hero:
  name: cpe-skills
  text: 面向网络安全与 AI 的 CPE 工具包
  tagline: 全面的 CPE（通用平台枚举）工具包 —— 解析、匹配、生成、漏洞关联、SBOM，以及 4 条集成路径（SKILLS / Go SDK / CLI / MCP）。
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/guide/basic-parsing
    - theme: alt
      text: API 参考
      link: /zh/api/
    - theme: alt
      text: 命令行
      link: /zh/cli/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cpe-skills

features:
  - icon: 🧩
    title: CPE 解析与格式化
    details: 自动识别 CPE 2.2 URI / 2.3 Formatted String，双向转换，WFN 绑定与转义（NISTIR 7695）。
  - icon: 🎯
    title: NISTIR 7696 匹配
    details: exact / subset / superset / disjoint 关系，外加模糊、正则、部分、距离匹配，支持批量。
  - icon: 🛠️
    title: 生成与构建器
    details: 从产品信息、模板、模糊输入生成 CPE；流畅的 Builder API 与随机生成器。
  - icon: 🛡️
    title: 漏洞关联
    details: 多源数据 —— NVD、OSV、EPSS 概率评分、CISA KEV 已知被利用漏洞。
  - icon: 📦
    title: SBOM 与供应链
    details: CycloneDX / SPDX 生成与解析，CPE ↔ PURL 双向映射，依赖图，manifest 解析。
  - icon: ⚡
    title: 风险评分与 VEX
    details: EPSS + KEV + 可达性感知的优先级排序，VEX 声明，多格式导出（JSON / CSV / SARIF）。
  - icon: 🤖
    title: AI 优先集成
    details: 4 条路径 —— SKILLS（AI/LLM 一键接入）、Go SDK、CLI、MCP 服务。专为 AI Agent 直接消费而设计。
  - icon: 🌐
    title: 108 平台二进制
    details: 9 个操作系统 × 13 种架构（含 ARM v5/6/7、MIPS 浮点变体、RISC-V、LoongArch、s390x），由 goreleaser 构建。
---

## 为什么选择 cpe-skills？

CPE 是 NIST 标准命名方案（NIST IR 7695/7696），用于标识 IT 系统和软件 —— 它是 CVE 漏洞匹配、SBOM 跟踪和供应链安全的基石。但 CPE 很难用：两种不兼容格式、复杂的 WFN 绑定、多源漏洞数据、SBOM 桥接。

**cpe-skills 解决了这一切** —— 单一工具包覆盖从解析到漏洞管理的完整 CPE 生命周期。

## 四条集成路径

```mermaid
flowchart LR
    subgraph Consumers
        A[AI / LLM Agent]
        B[Go 应用]
        C[Shell / CI]
        D[MCP 客户端]
    end
    subgraph cpe-skills
        S[SKILLS<br/>自然语言]
        K[Go SDK<br/>类型安全 API]
        C2[CLI<br/>cpe 命令]
        M[MCP 服务<br/>协议]
    end
    A --> S
    B --> K
    C --> C2
    D --> M
    S --> Core[(CPE 核心引擎)]
    K --> Core
    C2 --> Core
    M --> Core
```

### 1. SKILLS —— 面向 AI / LLM

添加到你的 Claude Code skills 配置：

```text
https://github.com/scagogogo/cpe-skills
```

### 2. Go SDK

```bash
go get github.com/scagogogo/cpe-skills
```

```go
c, _ := cpeskills.Parse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
fmt.Println(c.Vendor, c.ProductName, c.Version)
```

### 3. CLI

```bash
# 通过 Go 安装
go install github.com/scagogogo/cpe-skills/cmd/cpe@latest

# 或从 Releases 下载预编译二进制（108 个平台）
cpe parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
cpe match "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" \
         "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
```

### 4. MCP（模型上下文协议）

```json
{
  "mcpServers": {
    "cpe-skills": {
      "command": "cpe",
      "args": ["mcp", "serve"]
    }
  }
}
```

## 数据流

```mermaid
flowchart TD
    P[CPE 字符串<br/>2.2 / 2.3] --> Parse[解析与校验]
    Parse --> Match[NISTIR 7696 匹配]
    Parse --> Gen[生成 / 构建]
    Match --> Vuln[漏洞关联]
    Vuln --> NVD[NVD]
    Vuln --> OSV[OSV]
    Vuln --> EPSS[EPSS]
    Vuln --> KEV[CISA KEV]
    Parse --> SBOM[SBOM / PURL]
    Vuln --> Risk[风险评分]
    SBOM --> Risk
    Risk --> Export[导出 JSON / CSV / SARIF / VEX]
```

## 架构

```mermaid
flowchart LR
    subgraph Input
        S1[CPE 2.2 URI]
        S2[CPE 2.3 FS]
        S3[产品信息]
        S4[Lockfile / Manifest]
    end
    subgraph Core["CPE 核心引擎"]
        P[解析与校验]
        M[NISTIR 7696 匹配]
        G[生成 / 构建]
        W[WFN 绑定与转义]
        N[归一化]
    end
    subgraph Correlation["漏洞关联"]
        V[漏洞]
        NVD[NVD]
        OSV[OSV]
        EPSS[EPSS]
        KEV[CISA KEV]
    end
    subgraph SupplyChain["供应链"]
        SB[SBOM CycloneDX/SPDX]
        PU[CPE ↔ PURL]
        DG[依赖图]
    end
    subgraph Output["输出"]
        R[风险与 VEX]
        E[导出 JSON/CSV/SARIF]
    end
    S1 --> P
    S2 --> P
    S3 --> G
    S4 --> SB
    P --> M
    P --> W
    P --> N
    M --> V
    V --> NVD
    V --> OSV
    V --> EPSS
    V --> KEV
    SB --> PU
    SB --> DG
    V --> R
    SB --> R
    R --> E
```

## 功能脑图

```mermaid
mindmap
  root((cpe-skills))
    解析
      CPE 2.2 URI
      CPE 2.3 FS
      自动识别
      WFN 绑定
    匹配
      NISTIR 7696
      Exact / Subset / Superset
      模糊与正则
      批量
    生成
      从产品信息
      模板
      Fluent Builder
      模糊生成
    漏洞
      NVD
      OSV
      EPSS 评分
      CISA KEV
    SBOM
      CycloneDX
      SPDX
      CPE ↔ PURL
      依赖图
    风险与 VEX
      风险评分
      可达性
      VEX 声明
      修复建议
    导出
      JSON
      CSV
      SARIF
      SBOM 格式
    基础设施
      CPE 集合
      适用性
      结构化错误
      日志
```

## 文档

- [使用指南](/zh/guide/) — 实用使用示例
- [API 参考](/zh/api/) — 完整 API 文档
- [GitHub 仓库](https://github.com/scagogogo/cpe-skills) — 源码、发布、问题
