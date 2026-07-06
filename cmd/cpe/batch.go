package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// batch.go — `cpe batch match --criteria file --targets file` → BatchMatchCPEs
//            `cpe batch scan --sbom sbom.json --nvd cache.json` → NewCPEIndex + NewBatchScanner + Scan
// 批量匹配：评估多个 criteria CPE 与多个 target CPE 的匹配关系。

var (
	batchCriteriaFile string
	batchTargetsFile  string
	batchSBOMFile     string
	batchNVDFile      string
	batchConcurrency  int
)

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Batch CPE matching and scanning",
	Long: `Match and scan CPEs in bulk.

Subcommands:
  batch match --criteria <file> --targets <file>  Match criteria CPEs against targets
  batch scan --sbom <file> --nvd <file>           Scan SBOM components against NVD

Files contain one CPE per line.

Examples:
  cpe batch match --criteria crits.txt --targets targets.txt
  cpe batch scan --sbom sbom.json --nvd nvd.json --concurrency 4
  cpe batch match -o json --criteria crits.txt --targets targets.txt`,
}

var batchMatchCmd = &cobra.Command{
	Use:   "match",
	Short: "Match criteria CPEs against targets",
	RunE:  runBatchMatch,
}

var batchScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan SBOM components against NVD data",
	RunE:  runBatchScan,
}

func init() {
	batchMatchCmd.Flags().StringVar(&batchCriteriaFile, "criteria", "", "File with criteria CPEs (one per line)")
	batchMatchCmd.Flags().StringVar(&batchTargetsFile, "targets", "", "File with target CPEs (one per line)")
	batchMatchCmd.MarkFlagRequired("criteria")
	batchMatchCmd.MarkFlagRequired("targets")

	batchScanCmd.Flags().StringVar(&batchSBOMFile, "sbom", "", "SBOM JSON file")
	batchScanCmd.Flags().StringVar(&batchNVDFile, "nvd", "", "NVD data JSON file")
	batchScanCmd.Flags().IntVarP(&batchConcurrency, "concurrency", "c", 4, "Concurrency level")
	batchScanCmd.MarkFlagRequired("sbom")
	batchScanCmd.MarkFlagRequired("nvd")

	batchCmd.AddCommand(batchMatchCmd)
	batchCmd.AddCommand(batchScanCmd)
	rootCmd.AddCommand(batchCmd)
}

func runBatchMatch(cmd *cobra.Command, args []string) error {
	criteria, err := readCPEsFromFile(batchCriteriaFile)
	if err != nil {
		return fmt.Errorf("read criteria: %w", err)
	}
	targets, err := readCPEsFromFile(batchTargetsFile)
	if err != nil {
		return fmt.Errorf("read targets: %w", err)
	}

	results := cpeskills.BatchMatchCPEs(criteria, targets)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Match Results (%d):\n", len(results))
	for _, r := range results {
		criteriaStr := "unknown"
		if r.Criteria != nil {
			criteriaStr = r.Criteria.GetURI()
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s matched %d targets\n", criteriaStr, r.Count)
	}
	return nil
}

func runBatchScan(cmd *cobra.Command, args []string) error {
	// 加载 SBOM
	sbomData, err := os.ReadFile(batchSBOMFile)
	if err != nil {
		return fmt.Errorf("read SBOM: %w", err)
	}
	var sbom cpeskills.SBOM
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// 用 NVD 数据建立 CPE index，再用 BatchScanner 扫描
	nvdData, err := loadNVDData(batchNVDFile)
	if err != nil {
		return fmt.Errorf("load NVD data: %w", err)
	}

	// 从 NVD 提取 CPE 列表建索引
	var nvdCPEs []*cpeskills.CPE
	if nvdData.CPEMatchData != nil {
		for _, uris := range nvdData.CPEMatchData.CVEToCPEs {
			for _, uri := range uris {
				if c, parseErr := parseCPEString(uri); parseErr == nil {
					nvdCPEs = append(nvdCPEs, c)
				}
			}
		}
	}

	index := cpeskills.NewCPEIndex(nvdCPEs)
	scanner := cpeskills.NewBatchScanner(index, batchConcurrency)
	results, err := scanner.Scan(sbom.Components)
	if err != nil {
		return fmt.Errorf("batch scan: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Scan Results (%d components):\n", len(results))
	for _, r := range results {
		compName := "unknown"
		if r.Component != nil {
			compName = r.Component.Name
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s: %d findings\n", compName, len(r.Vulnerabilities))
	}
	return nil
}

// readCPEsFromFile 从文件读取 CPE 列表（每行一个）
func readCPEsFromFile(path string) ([]*cpeskills.CPE, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(string(data))
	var cpes []*cpeskills.CPE
	for _, line := range lines {
		c, err := parseCPEString(line)
		if err != nil {
			continue
		}
		cpes = append(cpes, c)
	}
	return cpes, nil
}
