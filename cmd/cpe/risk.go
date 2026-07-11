package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// risk.go — `cpe risk score --sbom sbom.json --nvd cache.json` → ScoreComponents + SortByRisk
//            `cpe risk score ... --priority critical` → FilterByPriority
// 风险评分：基于 SBOM 组件 + NVD 数据，输出每个组件的风险评分和优先级。

var (
	riskSBOMFile string
	riskNVDFile  string
	riskPriority string
)

var riskCmd = &cobra.Command{
	Use:   "risk",
	Short: "Risk scoring for SBOM components",
	Long: `Score the risk of SBOM components using NVD vulnerability data.

Subcommands:
  risk score --sbom <file> --nvd <file>  Score all components
    Use --priority critical|high|medium|low to filter by priority.

Examples:
  cpe risk score --sbom sbom.json --nvd nvd.json
  cpe risk score --sbom sbom.json --nvd nvd.json --priority critical
  cpe risk score -o json --sbom sbom.json --nvd nvd.json`,
}

var riskScoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Score risk of SBOM components",
	RunE:  runRiskScore,
}

func init() {
	riskScoreCmd.Flags().StringVar(&riskSBOMFile, "sbom", "", "SBOM JSON file path")
	riskScoreCmd.Flags().StringVar(&riskNVDFile, "nvd", "", "NVD data JSON file path")
	riskScoreCmd.Flags().StringVar(&riskPriority, "priority", "", "Filter by priority: critical, high, medium, low")
	riskScoreCmd.MarkFlagRequired("sbom")
	riskScoreCmd.MarkFlagRequired("nvd")

	riskCmd.AddCommand(riskScoreCmd)
	rootCmd.AddCommand(riskCmd)
}

func runRiskScore(cmd *cobra.Command, args []string) error {
	// 加载 SBOM
	sbomData, err := os.ReadFile(riskSBOMFile)
	if err != nil {
		return fmt.Errorf("read SBOM: %w", err)
	}
	var sbom cpeskills.SBOM
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	// 加载 NVD data
	nvdData, err := loadNVDData(riskNVDFile)
	if err != nil {
		return fmt.Errorf("load NVD data: %w", err)
	}

	scores := cpeskills.ScoreComponents(sbom.Components, nvdData)
	cpeskills.SortByRisk(scores)

	if riskPriority != "" {
		scores = cpeskills.FilterByPriority(scores, cpeskills.RiskPriority(riskPriority))
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(scores)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Risk Scores (%d components):\n", len(scores))
	for _, s := range scores {
		compName := "unknown"
		compVer := "unknown"
		if s.Component != nil {
			compName = s.Component.Name
			compVer = s.Component.Version
		}
		fmt.Fprintf(cmd.OutOrStdout(), "  %s (%s): score=%.2f priority=%s\n",
			compName, compVer, s.OverallScore, s.Priority)
	}
	return nil
}
