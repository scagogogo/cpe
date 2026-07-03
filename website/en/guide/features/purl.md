---
title: PURL & Ecosystem
outline: deep
---

# 🔗 PURL & Ecosystem

A **Package URL (PURL)** is the canonical identifier for a package across ecosystems (`pkg:maven/...`, `pkg:npm/...`, `pkg:golang/...`). `cpeskills` parses PURLs, maps them to ecosystems, and converts bidirectionally between PURL and CPE — letting you bridge the NVD world (CPE) with the package-manager world (PURL).

## Concept

Conversion is lossy: a CPE carries vendor + product + version, while a PURL carries type + namespace + name + version. The library returns a **confidence score** (0.0–1.0) for each conversion so you know when the mapping is uncertain.

```mermaid
flowchart LR
    C["CPE"] -->|"CPEToPURL<br/>(purl, confidence, err)"| P["PackageURL"]
    P -->|"PURLToCPE<br/>(cpe, confidence, err)"| C
    P -->|"Ecosystem()"| E["Ecosystem<br/>(Maven/NPM/Go/...)"]
    R["raw PURL string"] -->|"ParsePURL"| P
    N["type/ns/name/ver"|] -->|"NewPURL"| P
```

## Parse, Build, and Inspect

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
    fmt.Printf("ecosystem=%s\n", purl.Ecosystem())

    built := cpeskills.NewPURL("npm", "", "lodash", "4.17.21")
    fmt.Println(built.String())
}
```

## Convert Between CPE and PURL

```go
cpe := cpeskills.MustParse("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")

purl, conf, err := cpeskills.CPEToPURL(cpe)
if err == nil && conf > 0.5 {
    fmt.Printf("mapped to %s (confidence %.2f)\n", purl.String(), conf)
}

back, conf2, err := cpeskills.PURLToCPE(purl)
if err == nil {
    fmt.Printf("back to CPE %s (confidence %.2f)\n", back.String(), conf2)
}
```

## Best Practices

- **Check the confidence score** — below ~0.5 the vendor/product inference is uncertain; prefer keeping the original identifier.
- **Store both CPE and PURL on SBOM components** (`SetCPE` + `SetPURL`) so enrichment and ecosystem tooling each have the right key.
- **Use `Ecosystem()` to dispatch logic** (e.g. Maven vs Go fix-database lookups) rather than string-matching the PURL type.

## Related Modules

- [SBOM](./sbom.md) — `SetCPE` / `SetPURL` attach both identifiers to a component.
- [Manifest to SBOM](./manifest.md) — manifest parsers produce PURLs per component.
- [Basic Parsing](../basic-parsing.md) — CPE parsing that feeds `CPEToPURL`.
