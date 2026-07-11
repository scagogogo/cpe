package cpeskills

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
)

// ExportFormat 导出格式
type ExportFormat string

const (
	// ExportFormatJSON JSON 格式导出
	ExportFormatJSON ExportFormat = "json"

	// ExportFormatCSV CSV 格式导出
	ExportFormatCSV ExportFormat = "csv"

	// ExportFormatSARIF SARIF 格式导出 (Static Analysis Results Interchange Format)
	ExportFormatSARIF ExportFormat = "sarif"
)

// ExportVulnerabilityReport 导出漏洞报告到指定格式
func ExportVulnerabilityReport(report *VulnerabilityReport, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportFormatJSON:
		return ExportToJSON(report)
	case ExportFormatCSV:
		return ExportToCSV([]*VulnerabilityReport{report})
	case ExportFormatSARIF:
		return ExportToSARIF([]*VulnerabilityReport{report})
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ExportToJSON 导出漏洞报告为 JSON
func ExportToJSON(report *VulnerabilityReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("report is nil")
	}
	return json.MarshalIndent(report, "", "  ")
}

// ExportToCSV 导出漏洞报告为 CSV
func ExportToCSV(reports []*VulnerabilityReport) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// 写入表头
	header := []string{
		"Component", "Version", "CVE", "Severity", "CVSS",
		"EPSS", "KEV", "Reachability", "FixAvailable", "FixedVersion",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// 写入数据行
	for _, report := range reports {
		if report == nil || report.Component == nil {
			continue
		}

		compName := report.Component.Name
		compVersion := report.Component.Version

		for _, finding := range report.Vulnerabilities {
			cveID := ""
			severity := ""
			cvss := ""
			epss := ""
			kev := "false"
			fixAvailable := "false"
			fixedVersion := ""

			if finding.CVE != nil {
				cveID = finding.CVE.CVEID
				severity = finding.CVE.Severity
				cvss = fmt.Sprintf("%.1f", finding.CVE.CVSSScore)
			}
			if finding.EPSSScore > 0 {
				epss = fmt.Sprintf("%.4f", finding.EPSSScore)
			}
			if finding.KEVListed {
				kev = "true"
			}
			if finding.FixedVersion != "" {
				fixAvailable = "true"
				fixedVersion = finding.FixedVersion
			}

			row := []string{
				compName, compVersion, cveID, severity, cvss,
				epss, kev, finding.Reachability, fixAvailable, fixedVersion,
			}
			if err := writer.Write(row); err != nil {
				return nil, err
			}
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// ExportToSARIF 导出漏洞报告为 SARIF 格式
//
// SARIF 是 OASIS 标准的静态分析结果交换格式，被 GitHub、Azure DevOps 等广泛支持。
func ExportToSARIF(reports []*VulnerabilityReport) ([]byte, error) {
	type sarifMessage struct {
		Text string `json:"text"`
	}

	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}

	type sarifPhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region sarifRegion `json:"region"`
	}

	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}

	type sarifResult struct {
		RuleID    string          `json:"ruleId"`
		Level     string          `json:"level"`
		Message   sarifMessage    `json:"message"`
		Locations []sarifLocation `json:"locations,omitempty"`
	}

	type sarifToolComponent struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	type sarifTool struct {
		Driver sarifToolComponent `json:"driver"`
	}

	type sarifRun struct {
		Tool    sarifTool      `json:"tool"`
		Results []*sarifResult `json:"results"`
	}

	type sarifRoot struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}

	root := sarifRoot{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifToolComponent{
						Name:    "cpe-skills",
						Version: "1.0.0",
					},
				},
				Results: make([]*sarifResult, 0),
			},
		},
	}

	for _, report := range reports {
		if report == nil || report.Component == nil {
			continue
		}

		for _, finding := range report.Vulnerabilities {
			cveID := "unknown"
			severity := "warning"
			description := "Vulnerability found"

			if finding.CVE != nil {
				cveID = finding.CVE.CVEID
				description = finding.CVE.Description
				switch finding.CVE.Severity {
				case "Critical":
					severity = "error"
				case "High":
					severity = "error"
				case "Medium":
					severity = "warning"
				default:
					severity = "note"
				}
			}

			result := &sarifResult{
				RuleID: cveID,
				Level:  severity,
				Message: sarifMessage{
					Text: fmt.Sprintf("%s@%s: %s", report.Component.Name, report.Component.Version, description),
				},
				Locations: []sarifLocation{
					{
						PhysicalLocation: sarifPhysicalLocation{
							ArtifactLocation: struct {
								URI string `json:"uri"`
							}{URI: report.Component.Name},
							Region: sarifRegion{StartLine: 1},
						},
					},
				},
			}

			root.Runs[0].Results = append(root.Runs[0].Results, result)
		}
	}

	return json.MarshalIndent(root, "", "  ")
}

// ExportSBOMToCycloneDX 导出 SBOM 为 CycloneDX 格式
func ExportSBOMToCycloneDX(sbom *SBOM) ([]byte, error) {
	return sbom.ToCycloneDXJSON()
}

// ExportSBOMToSPDX 导出 SBOM 为 SPDX 格式
func ExportSBOMToSPDX(sbom *SBOM) ([]byte, error) {
	return sbom.ToSPDXJSON()
}

// ExportVulnerabilityReportBatch 批量导出漏洞报告
func ExportVulnerabilityReportBatch(reports []*VulnerabilityReport, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportFormatJSON:
		return json.MarshalIndent(reports, "", "  ")
	case ExportFormatCSV:
		return ExportToCSV(reports)
	case ExportFormatSARIF:
		return ExportToSARIF(reports)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}
