---
title: Migrating from CPE 2.2 to 2.3
outline: deep
---

# 🔄 Migrating from CPE 2.2 to 2.3

CPE 2.2 (the URI style, `cpe:/a:microsoft:windows`) is legacy. CPE 2.3 (the Formatted String, `cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*`) is what NVD publishes and what modern tooling expects. This page shows how to move.

## Why migrate

CPE 2.3 adds four attribute fields that 2.2 cannot express, and it is the canonical format for NVD, SBOM standards, and the matching specification. 2.2 cannot distinguish, for example, two editions of the same product version.

| Field (2.3)        | 2.2 equivalent | Notes                              |
|--------------------|----------------|------------------------------------|
| `part`             | `part`         | same `a`/`o`/`h`                   |
| `vendor`           | `vendor`       | same                               |
| `product`          | `product`      | same                               |
| `version`          | `version`      | same                               |
| `update`           | `update`       | same                               |
| `edition`          | `edition`      | same                               |
| `language`         | `language`     | same                               |
| `sw_edition`       | —              | **new in 2.3**                     |
| `target_sw`        | —              | **new in 2.3**                     |
| `target_hw`        | —              | **new in 2.3**                     |
| `other`            | —              | **new in 2.3**                     |

When a 2.2 name is converted to 2.3, the four new fields default to `*` (ANY).

## Conversion via Parse + Format

`ParseCpe22` reads a 2.2 URI into a `CPE` struct; `FormatCpe23` writes that struct back out as a 2.3 Formatted String. The `CPE` struct is format-agnostic, so it is the natural bridge.

```go
import "github.com/scagogogo/cpe-skills"

c, err := cpeskills.ParseCpe22("cpe:/a:microsoft:windows:10")
if err != nil {
    log.Fatal(err)
}
fmt.Println(cpeskills.FormatCpe23(c))
// cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
```

`FormatCPE(c, "2.3")` does the same thing and `FormatCPE(c, "2.2")` goes the other way, which is handy when the target format is a runtime parameter.

```mermaid
flowchart LR
    A["cpe:/a:vendor:product:1.0"] -->|ParseCpe22| B[CPE struct]
    B -->|FormatCpe23| C["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    B -->|FormatCpe22| A
    B -->|FromCPE| D[WFN]
    D -->|ToCPE23String| C
```

## The WFN intermediate representation

Both parsers ultimately build a **Well-Formed Name** (WFN) internally, and both formatters read from one. `FromCPE` and `WFN.ToCPE` let you manipulate the canonical form directly — useful when you need to set a field that only exists in 2.3 before re-serialising.

```go
w := cpeskills.FromCPE(c)            // CPE -> WFN
w.Set(cpeskills.AttrSoftwareEdition, "enterprise")
c2 := w.ToCPE()                      // WFN -> CPE (2.3 fields populated)
fmt.Println(cpeskills.FormatCpe23(c2))
```

See [/en/api/modules/parser-2.2](/en/api/modules/parser-2.2), [/en/api/modules/parser-2.3](/en/api/modules/parser-2.3), and [/en/api/modules/wfn](/en/api/modules/wfn).

## Migration checklist

1. Replace `cpe:/` literals with `cpe:2.3:` in any data you control.
2. For inbound 2.2 data, run `ParseCpe22` then `FormatCpe23` on ingest and store only 2.3.
3. Populate `sw_edition` / `target_sw` / `target_hw` where you know them — they improve match accuracy.
4. Update match logic to expect the 2.3 field count (11 colon-separated components).
5. Keep the legacy field for one release, then drop it.

## Summary

Migrate by parsing 2.2 with `ParseCpe22`, normalising through the shared `CPE`/`WFN` model, and re-emitting with `FormatCpe23`. The four new 2.3 fields default to ANY and should be filled where known. Parser modules: [/en/api/modules/parser-2.2](/en/api/modules/parser-2.2), [/en/api/modules/parser-2.3](/en/api/modules/parser-2.3); WFN: [/en/api/modules/wfn](/en/api/modules/wfn).
