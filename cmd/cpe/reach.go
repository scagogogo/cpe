package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// reach.go — `cpe reach analyze --sbom sbom.json --nvd cache.json` → 建图 + 可达性分析
// 可达性分析：评估漏洞是否可通过依赖路径到达应用入口。

var (
	reachSBOMFile string
	reachNVDFile  string
)

var reachCmd = &cobra.Command{
	Use:   "reach",
	Short: "Reachability analysis for vulnerabilities",
	Long: `Analyze whether vulnerabilities are reachable through dependency paths.

Reachability analysis helps prioritize remediation by identifying
vulnerabilities that can actually be exploited via call paths.

Subcommands:
  reach analyze --sbom <file> --nvd <file>  Run reachability analysis

Examples:
  cpe reach analyze --sbom sbom.json --nvd nvd.json
  cpe reach analyze -o json --sbom sbom.json --nvd nvd.json`,
}

var reachAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Run reachability analysis",
	RunE:  runReachAnalyze,
}

func init() {
	reachAnalyzeCmd.Flags().StringVar(&reachSBOMFile, "sbom", "", "SBOM JSON file")
	reachAnalyzeCmd.Flags().StringVar(&reachNVDFile, "nvd", "", "NVD data JSON file")
	reachAnalyzeCmd.MarkFlagRequired("sbom")
	reachAnalyzeCmd.MarkFlagRequired("nvd")

	reachCmd.AddCommand(reachAnalyzeCmd)
	rootCmd.AddCommand(reachCmd)
}

func runReachAnalyze(cmd *cobra.Command, args []string) error {
	// 加载 SBOM 并建依赖图
	graph, err := loadSBOMGraph(reachSBOMFile)
	if err != nil {
		return fmt.Errorf("load SBOM graph: %w", err)
	}

	// 加载 NVD 数据
	nvdData, err := loadNVDData(reachNVDFile)
	if err != nil {
		return fmt.Errorf("load NVD data: %w", err)
	}

	// 从依赖图找漏洞
	findings := graph.FindTransitiveVulnerabilities(nvdData)

	// 运行可达性分析
	analyzer := cpeskills.NewDependencyGraphReachabilityAnalyzer()
	results, err := analyzer.Analyze(graph, findings)
	if err != nil {
		return fmt.Errorf("reachability analysis: %w", err)
	}

	// 汇总
	summary := cpeskills.SummarizeReachability(results)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"total":       len(results),
			"direct":      summary.Direct,
			"transitive":  summary.Transitive,
			"conditional": summary.Conditional,
			"notReachable": summary.NotReachable,
			"results":     results,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Reachability Analysis:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Total findings:   %d\n", len(results))
	fmt.Fprintf(cmd.OutOrStdout(), "  Direct:           %d\n", summary.Direct)
	fmt.Fprintf(cmd.OutOrStdout(), "  Transitive:       %d\n", summary.Transitive)
	fmt.Fprintf(cmd.OutOrStdout(), "  Not reachable:    %d\n", summary.NotReachable)
	return nil
}