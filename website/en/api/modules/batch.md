---
title: Batch
outline: deep
---

# 📦 Batch Scanning

The `batch` module supports concurrent scanning of SBOM components against a `CPEIndex` and one or more vulnerability data sources, plus standalone batch helpers for CPE matching, PURL-to-CPE resolution, and CVE lookups.

## Type: ScanResult

```go
type ScanResult struct {
    Component        *SBOMComponent          `json:"component"`
    Vulnerabilities  []*VulnerabilityFinding `json:"vulnerabilities"`
    RiskScore        *RiskScore              `json:"riskScore,omitempty"`
    Duration         time.Duration           `json:"duration"`
    Error            string                  `json:"error,omitempty"`
}
```

The outcome of scanning a single `SBOMComponent`: the component itself, the vulnerability findings discovered, an optional risk score, the scan duration, and an error string (if any).

## Type: BatchScanner

```go
type BatchScanner struct {
    Index        *CPEIndex
    DataSources  []*VulnDataSource
    Scorer       RiskScorer
    Concurrency  int
}
```

A concurrent scanner over a `CPEIndex` and a set of vulnerability data sources. `Concurrency` controls the goroutine count. Construct with `NewBatchScanner`; configure data sources with `SetDataSources`.

## Type: MatchResult

```go
type MatchResult struct {
    Criteria *CPE   `json:"criteria"`
    Targets  []*CPE `json:"targets"`
    Count    int    `json:"count"`
}
```

The result of matching a single criteria CPE against a target list: the criteria, the matched targets, and the count.

## 🏗️ NewBatchScanner

```go
func NewBatchScanner(index *CPEIndex, concurrency int) *BatchScanner
```

Creates a `BatchScanner` backed by `index`. When `concurrency <= 0` it defaults to `4`. The scanner is initialized with the default risk scorer (`NewDefaultRiskScorer`).

| Parameter | Type | Description |
| --- | --- | --- |
| `index` | `*CPEIndex` | The CPE index used for lookups, may be `nil` |
| `concurrency` | `int` | Maximum concurrent scans; `<= 0` becomes `4` |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `*BatchScanner` | The configured scanner |

```go
index := cpeskills.NewCPEIndex(cpes)
scanner := cpeskills.NewBatchScanner(index, 8)
```

## 🔌 SetDataSources

```go
func (bs *BatchScanner) SetDataSources(sources []*VulnDataSource)
```

Replaces the scanner's vulnerability data sources. Each non-`nil` source is queried per component via `SearchVulnerabilitiesByCPE`.

| Parameter | Type | Description |
| --- | --- | --- |
| `sources` | `[]*VulnDataSource` | The data sources to use |

```go
scanner.SetDataSources([]*cpeskills.VulnDataSource{nvdSource, osvSource})
```

## 🚀 Scan

```go
func (bs *BatchScanner) Scan(components []*SBOMComponent) ([]*ScanResult, error)
```

Scans every component concurrently (bounded by `bs.Concurrency`) and returns one `ScanResult` per component, preserving input order. For each component the scanner: looks up the component's CPE in `bs.Index` (when both are non-`nil`); queries each data source for vulnerabilities by CPE; and, when a risk scorer is set and findings exist, computes a risk score. Currently the returned error is always `nil`; per-component failures are captured in `ScanResult.Error`.

| Parameter | Type | Description |
| --- | --- | --- |
| `components` | `[]*SBOMComponent` | The components to scan |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]*ScanResult` | One result per component, in input order |
| #2 | `error` | Always `nil` in the current implementation |

```go
scanner := cpeskills.NewBatchScanner(index, 8)
scanner.SetDataSources(sources)
results, err := scanner.Scan(components)
if err != nil {
    log.Fatal(err)
}
for _, r := range results {
    fmt.Printf("%s: %d vulnerabilities, risk %v\n",
        r.Component.Name, len(r.Vulnerabilities), r.RiskScore)
}
```

## 🎯 BatchMatchCPEs

```go
func BatchMatchCPEs(criteria []*CPE, targets []*CPE) []MatchResult
```

Matches every CPE in `criteria` against `targets` using an internally-built `CPEIndex` for acceleration. Returns one `MatchResult` per criteria entry, in the same order.

| Parameter | Type | Description |
| --- | --- | --- |
| `criteria` | `[]*CPE` | The criteria CPEs to match |
| `targets` | `[]*CPE` | The CPE list to search within |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]MatchResult` | One match result per criteria, in order |

```go
criteria := []*cpeskills.CPE{
    cpeskills.MustParse("cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*"),
    cpeskills.MustParse("cpe:2.3:a:adobe:reader:*:*:*:*:*:*:*:*"),
}
results := cpeskills.BatchMatchCPEs(criteria, allCPEs)
for _, r := range results {
    fmt.Printf("criteria matched %d targets\n", r.Count)
}
```

## 🏷️ BatchMatchPURLs

```go
func BatchMatchPURLs(purls []*PackageURL, cpes []*CPE) map[string]*CPE
```

Resolves each PURL to a CPE by first consulting an index built from `cpes` (`LookupByPURL`), and falling back to `PURLToCPE` conversion followed by an index lookup. The returned map is keyed by the PURL's string form (`purl.String()`). `nil` PURLs are skipped, and PURLs with no match are omitted from the map.

| Parameter | Type | Description |
| --- | --- | --- |
| `purls` | `[]*PackageURL` | The package URLs to resolve |
| `cpes` | `[]*CPE` | The CPE universe to match against |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string]*CPE` | PURL string → matched CPE |

```go
purls := []*cpeskills.PackageURL{pkgURL1, pkgURL2}
mapping := cpeskills.BatchMatchPURLs(purls, allCPEs)
for purlStr, cpe := range mapping {
    fmt.Printf("%s -> %s\n", purlStr, cpe.GetURI())
}
```

## 📋 BatchQueryCVEs

```go
func BatchQueryCVEs(cveIDs []string, dataSources []*VulnDataSource) (map[string]*CVEReference, error)
```

Looks up detailed CVE information for each CVE ID across the provided data sources using a multi-source search (concurrency level 5). The first data source returning a reference whose `CVEID` matches is kept. CVEs with no result are omitted from the map. Lookup errors for individual IDs are swallowed (the loop continues); the function currently always returns a `nil` error.

| Parameter | Type | Description |
| --- | --- | --- |
| `cveIDs` | `[]string` | The CVE IDs to query |
| `dataSources` | `[]*VulnDataSource` | The data sources to query |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `map[string]*CVEReference` | CVE ID → reference (only for IDs that resolved) |
| #2 | `error` | Always `nil` in the current implementation |

```go
ids := []string{"CVE-2021-44228", "CVE-2021-45046"}
refs, err := cpeskills.BatchQueryCVEs(ids, []*cpeskills.VulnDataSource{nvdSource})
if err != nil {
    log.Fatal(err)
}
for id, ref := range refs {
    fmt.Printf("%s: %s\n", id, ref.Description)
}
```

## 📐 Batch Scanning Flow Diagram

```mermaid
flowchart TD
    C[components] --> BS[BatchScanner.Scan]
    BS --> SEM[concurrency semaphore]
    SEM --> GO[per-component goroutine]
    GO --> IDX{Index non-nil?}
    IDX -->|yes| LK[Index.Lookup by CPE]
    IDX -->|no| DS
    LK --> DS[query each DataSource SearchVulnerabilitiesByCPE]
    DS --> F[VulnerabilityFinding list]
    F --> SC{Scorer set & findings?}
    SC -->|yes| RS[Score findings]
    SC -->|no| SR[ScanResult]
    RS --> SR
    SR --> OUT[[]ScanResult in order]
    BC[BatchMatchCPEs] --> IDX2[build CPEIndex from targets]
    IDX2 --> LK2[Lookup each criteria]
    LK2 --> MR[[]MatchResult]
    BP[BatchMatchPURLs] --> LBP[LookupByPURL or PURLToCPE]
    LBP --> PM[map string *CPE]
    BQ[BatchQueryCVEs] --> MSS[MultiSourceSearch level 5]
    MSS --> CRM[map string *CVEReference]
    style C fill:#e8f5e9,stroke:#2e7d32
    style OUT fill:#f3e5f5,stroke:#6a1b9a
    style MR fill:#f3e5f5,stroke:#6a1b9a
    style PM fill:#f3e5f5,stroke:#6a1b9a
    style CRM fill:#f3e5f5,stroke:#6a1b9a
```
