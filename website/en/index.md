---
layout: home

title: cpe-skills
titleTemplate: CPE Toolkit for Cybersecurity & AI Agents

hero:
  name: cpe-skills
  text: CPE Toolkit for Cybersecurity & AI
  tagline: A comprehensive CPE (Common Platform Enumeration) toolkit — parsing, matching, generation, vulnerability correlation, SBOM, and 4 integration paths (SKILLS / Go SDK / CLI / MCP).
  actions:
    - theme: brand
      text: Get Started
      link: /en/guide/basic-parsing
    - theme: alt
      text: API Reference
      link: /en/api/
    - theme: alt
      text: CLI
      link: /en/cli/
    - theme: alt
      text: GitHub
      link: https://github.com/scagogogo/cpe-skills

features:
  - icon: 🧩
    title: CPE Parsing & Formatting
    details: Auto-detect CPE 2.2 URI / 2.3 Formatted String, bidirectional conversion, WFN binding & escaping (NISTIR 7695).
  - icon: 🎯
    title: NISTIR 7696 Matching
    details: Exact / subset / superset / disjoint relations, plus fuzzy, regex, partial, and distance matching with batch support.
  - icon: 🛠️
    title: Generation & Builder
    details: Generate CPE from product info, templates, or fuzzy input; fluent Builder API and random generator.
  - icon: 🛡️
    title: Vulnerability Correlation
    details: Multi-source data — NVD, OSV, EPSS probability scoring, CISA KEV known-exploited vulnerabilities.
  - icon: 📦
    title: SBOM & Supply Chain
    details: CycloneDX / SPDX generation & parsing, CPE ↔ PURL bridging, dependency graph, manifest parsing.
  - icon: ⚡
    title: Risk Scoring & VEX
    details: EPSS + KEV + reachability-aware prioritization, VEX statements, multi-format export (JSON / CSV / SARIF).
  - icon: 🤖
    title: AI-First Integration
    details: 4 paths — SKILLS (one-click for AI/LLM), Go SDK, CLI, MCP server. Designed for AI agents to consume directly.
  - icon: 🌐
    title: 108 Platform Binaries
    details: 9 OSes × 13 architectures (incl. ARM v5/6/7, MIPS float variants, RISC-V, LoongArch, s390x) via goreleaser.
---

## Why cpe-skills?

CPE is the NIST-standard naming scheme (NIST IR 7695/7696) for identifying IT systems and software — it's the backbone of CVE vulnerability matching, SBOM tracking, and supply chain security. But working with CPE is hard: two incompatible formats, complex WFN binding, multi-source vulnerability data, SBOM bridging.

**cpe-skills solves all of this** with a single toolkit covering the full CPE lifecycle, from parsing to vulnerability management.

## Four Integration Paths

```mermaid
flowchart LR
    subgraph Consumers
        A[AI / LLM Agent]
        B[Go Application]
        C[Shell / CI]
        D[MCP Client]
    end
    subgraph cpe-skills
        S[SKILLS<br/>natural language]
        K[Go SDK<br/>type-safe API]
        C2[CLI<br/>cpe command]
        M[MCP Server<br/>protocol]
    end
    A --> S
    B --> K
    C --> C2
    D --> M
    S --> Core[(CPE Core Engine)]
    K --> Core
    C2 --> Core
    M --> Core
```

### 1. SKILLS — for AI / LLM

Add to your Claude Code skills configuration:

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
# Install via Go
go install github.com/scagogogo/cpe-skills/cmd/cpe@latest

# Or download a prebuilt binary from Releases (108 platforms)
cpe parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
cpe match "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" \
         "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
```

### 4. MCP (Model Context Protocol)

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

## Data Flow

```mermaid
flowchart TD
    P[CPE String<br/>2.2 / 2.3] --> Parse[Parse & Validate]
    Parse --> Match[NISTIR 7696 Matching]
    Parse --> Gen[Generate / Build]
    Match --> Vuln[Vulnerability Correlation]
    Vuln --> NVD[NVD]
    Vuln --> OSV[OSV]
    Vuln --> EPSS[EPSS]
    Vuln --> KEV[CISA KEV]
    Parse --> SBOM[SBOM / PURL]
    Vuln --> Risk[Risk Scoring]
    SBOM --> Risk
    Risk --> Export[Export JSON / CSV / SARIF / VEX]
```

## Architecture

```mermaid
flowchart LR
    subgraph Input
        S1[CPE 2.2 URI]
        S2[CPE 2.3 FS]
        S3[Product Info]
        S4[Lockfile / Manifest]
    end
    subgraph Core["CPE Core Engine"]
        P[Parse & Validate]
        M[NISTIR 7696 Match]
        G[Generate / Build]
        W[WFN Bind & Escape]
        N[Normalize]
    end
    subgraph Correlation
        V[Vulnerability]
        NVD[NVD]
        OSV[OSV]
        EPSS[EPSS]
        KEV[CISA KEV]
    end
    subgraph SupplyChain["Supply Chain"]
        SB[SBOM CycloneDX/SPDX]
        PU[CPE ↔ PURL]
        DG[Dependency Graph]
    end
    subgraph Output
        R[Risk & VEX]
        E[Export JSON/CSV/SARIF]
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

## Feature Mind Map

```mermaid
mindmap
  root((cpe-skills))
    Parsing
      CPE 2.2 URI
      CPE 2.3 FS
      Auto-detect
      WFN binding
    Matching
      NISTIR 7696
      Exact / Subset / Superset
      Fuzzy & Regex
      Batch
    Generation
      From product info
      Templates
      Fluent Builder
      Fuzzy generate
    Vulnerability
      NVD
      OSV
      EPSS scoring
      CISA KEV
    SBOM
      CycloneDX
      SPDX
      CPE ↔ PURL
      Dependency graph
    Risk & VEX
      Risk scoring
      Reachability
      VEX statements
      Remediation
    Export
      JSON
      CSV
      SARIF
      SBOM formats
    Infrastructure
      CPE Sets
      Applicability
      Structured errors
      Logging
```

## Documentation

- [Guide](/en/guide/) — Practical usage examples
- [API Reference](/en/api/) — Complete API documentation
- [GitHub Repository](https://github.com/scagogogo/cpe-skills) — Source code, releases, issues
