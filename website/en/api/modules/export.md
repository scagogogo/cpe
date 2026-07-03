---
title: Export Formats
outline: deep
---

# 📤 Export Formats

The `cpeskills` package provides functions to serialize vulnerability reports and SBOMs into industry-standard interchange formats: JSON, CSV, SARIF, CycloneDX and SPDX.

## Type: ExportFormat

```go
type ExportFormat string
```

A string enum selecting the output format for vulnerability report exports.

### Constants

| Constant | Type | Value | Description |
| --- | --- | --- | --- |
| `ExportFormatJSON` | `ExportFormat` | `"json"` | JSON format |
| `ExportFormatCSV` | `ExportFormat` | `"csv"` | CSV format |
| `ExportFormatSARIF` | `ExportFormat` | `"sarif"` | SARIF format (Static Analysis Results Interchange Format) |

```go
_ = cpeskills.ExportFormatJSON
_ = cpeskills.ExportFormatCSV
_ = cpeskills.ExportFormatSARIF
```

## 📄 ExportVulnerabilityReport

```go
func ExportVulnerabilityReport(report *VulnerabilityReport, format ExportFormat) ([]byte, error)
```

Exports a single vulnerability report to the specified format. Dispatches to the corresponding format-specific exporter.

| Parameter | Type | Description |
| --- | --- | --- |
| `report` | `*VulnerabilityReport` | The report to export |
| `format` | `ExportFormat` | The target format |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The serialized report bytes |
| #2 | `error` | An error if the format is unsupported or serialization fails |

```go
data, err := cpeskills.ExportVulnerabilityReport(report, cpeskills.ExportFormatJSON)
if err != nil {
    log.Fatal(err)
}
fmt.Println(string(data))
```

## 🔷 ExportToJSON

```go
func ExportToJSON(report *VulnerabilityReport) ([]byte, error)
```

Exports a vulnerability report as pretty-printed JSON (2-space indented).

| Parameter | Type | Description |
| --- | --- | --- |
| `report` | `*VulnerabilityReport` | The report to export |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The JSON bytes |
| #2 | `error` | An error if `report` is nil or marshaling fails |

```go
data, err := cpeskills.ExportToJSON(report)
```

## 📊 ExportToCSV

```go
func ExportToCSV(reports []*VulnerabilityReport) ([]byte, error)
```

Exports multiple vulnerability reports as CSV. The header row is `Component, Version, CVE, Severity, CVSS, EPSS, KEV, Reachability, FixAvailable, FixedVersion`, followed by one row per vulnerability finding.

| Parameter | Type | Description |
| --- | --- | --- |
| `reports` | `[]*VulnerabilityReport` | The reports to export |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The CSV bytes |
| #2 | `error` | An error if writing fails |

```go
data, err := cpeskills.ExportToCSV(reports)
```

## 🛡️ ExportToSARIF

```go
func ExportToSARIF(reports []*VulnerabilityReport) ([]byte, error)
```

Exports vulnerability reports as SARIF 2.1.0, the OASIS standard static-analysis results interchange format supported by GitHub and Azure DevOps. Critical/High severities map to `error`, Medium to `warning`, others to `note`.

| Parameter | Type | Description |
| --- | --- | --- |
| `reports` | `[]*VulnerabilityReport` | The reports to export |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The SARIF JSON bytes |
| #2 | `error` | An error if marshaling fails |

```go
data, err := cpeskills.ExportToSARIF(reports)
```

## 🔄 ExportSBOMToCycloneDX

```go
func ExportSBOMToCycloneDX(sbom *SBOM) ([]byte, error)
```

Exports an SBOM to CycloneDX JSON format (delegates to `sbom.ToCycloneDXJSON()`).

| Parameter | Type | Description |
| --- | --- | --- |
| `sbom` | `*SBOM` | The SBOM to export |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The CycloneDX JSON bytes |
| #2 | `error` | An error if serialization fails |

```go
data, err := cpeskills.ExportSBOMToCycloneDX(sbom)
```

## 📋 ExportSBOMToSPDX

```go
func ExportSBOMToSPDX(sbom *SBOM) ([]byte, error)
```

Exports an SBOM to SPDX JSON format (delegates to `sbom.ToSPDXJSON()`).

| Parameter | Type | Description |
| --- | --- | --- |
| `sbom` | `*SBOM` | The SBOM to export |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The SPDX JSON bytes |
| #2 | `error` | An error if serialization fails |

```go
data, err := cpeskills.ExportSBOMToSPDX(sbom)
```

## 📦 ExportVulnerabilityReportBatch

```go
func ExportVulnerabilityReportBatch(reports []*VulnerabilityReport, format ExportFormat) ([]byte, error)
```

Exports a batch of vulnerability reports in the specified format. For JSON it marshals the whole slice; for CSV/SARIF it delegates to the corresponding batch exporters.

| Parameter | Type | Description |
| --- | --- | --- |
| `reports` | `[]*VulnerabilityReport` | The reports to export |
| `format` | `ExportFormat` | The target format |

| Return | Type | Description |
| --- | --- | --- |
| #1 | `[]byte` | The serialized bytes |
| #2 | `error` | An error if the format is unsupported or serialization fails |

```go
data, err := cpeskills.ExportVulnerabilityReportBatch(reports, cpeskills.ExportFormatCSV)
```

## 🧭 Export Dispatch

```mermaid
flowchart LR
    R[VulnerabilityReport] --> EVR[ExportVulnerabilityReport]
    EVR -->|json| J[ExportToJSON]
    EVR -->|csv| C[ExportToCSV]
    EVR -->|sarif| S[ExportToSARIF]
    RB[[]*VulnerabilityReport] --> EVB[ExportVulnerabilityReportBatch]
    EVB -->|json| JB[json.MarshalIndent]
    EVB -->|csv| C
    EVB -->|sarif| S
    SBOM[SBOM] --> CDX[ExportSBOMToCycloneDX]
    SBOM --> SPX[ExportSBOMToSPDX]
    style EVR fill:#e8f5e9,stroke:#2e7d32
    style EVB fill:#e8f5e9,stroke:#2e7d32
```
