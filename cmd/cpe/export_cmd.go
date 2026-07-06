package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// export.go — `cpe export csv --sbom sbom.json --nvd cache.json -o out.csv` → ExportToCSV
//             `cpe export sarif ... -o out.sarif` → ExportToSARIF
// 导出漏洞报告为标准格式。

var (
	exportSBOMFile string
	exportNVDFile  string
	exportOutFile  string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export vulnerability reports to standard formats",
	Long: `Export vulnerability reports from SBOM + NVD data.

Subcommands:
  export csv   Export to CSV format
  export sarif Export to SARIF format

Examples:
  cpe export csv --sbom sbom.json --nvd nvd.json -o report.csv
  cpe export sarif --sbom sbom.json --nvd nvd.json -o report.sarif`,
}

var exportCSVCmd = &cobra.Command{
	Use:   "csv",
	Short: "Export to CSV format",
	RunE:  runExportCSV,
}

var exportSARIFCmd = &cobra.Command{
	Use:   "sarif",
	Short: "Export to SARIF format",
	RunE:  runExportSARIF,
}

func init() {
	for _, cmd := range []*cobra.Command{exportCSVCmd, exportSARIFCmd} {
		cmd.Flags().StringVar(&exportSBOMFile, "sbom", "", "SBOM JSON file path")
		cmd.Flags().StringVar(&exportNVDFile, "nvd", "", "NVD data JSON file path")
		cmd.Flags().StringVarP(&exportOutFile, "output", "o", "", "Output file path (default stdout)")
		cmd.MarkFlagRequired("sbom")
		cmd.MarkFlagRequired("nvd")
	}

	exportCmd.AddCommand(exportCSVCmd)
	exportCmd.AddCommand(exportSARIFCmd)
	rootCmd.AddCommand(exportCmd)
}

// buildVulnerabilityReports 从 SBOM + NVD 构建漏洞报告列表
func buildVulnerabilityReports(sbomFile, nvdFile string) ([]*cpeskills.VulnerabilityReport, error) {
	sbomData, err := os.ReadFile(sbomFile)
	if err != nil {
		return nil, fmt.Errorf("read SBOM: %w", err)
	}
	var sbom cpeskills.SBOM
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}

	nvdData, err := loadNVDData(nvdFile)
	if err != nil {
		return nil, fmt.Errorf("load NVD data: %w", err)
	}

	// 对每个组件生成报告
	var reports []*cpeskills.VulnerabilityReport
	for _, comp := range sbom.Components {
		report := &cpeskills.VulnerabilityReport{
			Component:       comp,
			Vulnerabilities: []*cpeskills.VulnerabilityFinding{},
			GeneratedAt:     time.Now(),
		}
		// 用 ScoreComponents 获取风险评分
		scores := cpeskills.ScoreComponents([]*cpeskills.SBOMComponent{comp}, nvdData)
		if len(scores) > 0 {
			report.RiskScore = scores[0].OverallScore
			report.MaxSeverity = string(scores[0].Priority)
		}
		reports = append(reports, report)
	}
	return reports, nil
}

func runExportCSV(cmd *cobra.Command, args []string) error {
	reports, err := buildVulnerabilityReports(exportSBOMFile, exportNVDFile)
	if err != nil {
		return err
	}

	data, err := cpeskills.ExportToCSV(reports)
	if err != nil {
		return fmt.Errorf("export CSV: %w", err)
	}

	if exportOutFile != "" {
		return os.WriteFile(exportOutFile, data, 0644)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func runExportSARIF(cmd *cobra.Command, args []string) error {
	reports, err := buildVulnerabilityReports(exportSBOMFile, exportNVDFile)
	if err != nil {
		return err
	}

	data, err := cpeskills.ExportToSARIF(reports)
	if err != nil {
		return fmt.Errorf("export SARIF: %w", err)
	}

	if exportOutFile != "" {
		return os.WriteFile(exportOutFile, data, 0644)
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}
