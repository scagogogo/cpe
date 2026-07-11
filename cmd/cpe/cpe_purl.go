package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// cpe_purl.go — `cpe cpe-to-purl <cpe>` → CPEToPURL (返回 *PackageURL + 置信度)
//               `cpe purl-to-cpe <purl>` → PURLToCPE (返回 *CPE + 置信度)
// CPE 与 PURL 之间的转换，置信度反映映射的确定性。

var cpeToPurlCmd = &cobra.Command{
	Use:   "cpe-to-purl <cpe-string>",
	Short: "Convert CPE to Package URL (with confidence score)",
	Long: `Convert a CPE 2.3 string to a Package URL (purl).

The conversion includes a confidence score (0.0-1.0) indicating
how certain the mapping is. Some CPEs map cleanly (confidence ~1.0),
others require heuristics (confidence < 1.0).

Examples:
  cpe cpe-to-purl "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
  cpe cpe-to-purl -o json "cpe:2.3:a:nginx:nginx:1.18:*:*:*:*:*:*:*"`,
	Args: cobra.ExactArgs(1),
	RunE: runCPEToPURL,
}

var purlToCpeCmd = &cobra.Command{
	Use:   "purl-to-cpe <purl-string>",
	Short: "Convert Package URL to CPE (with confidence score)",
	Long: `Convert a Package URL (purl) to a CPE 2.3 string.

The conversion includes a confidence score (0.0-1.0) indicating
how certain the mapping is.

Examples:
  cpe purl-to-cpe pkg:npm/left-pad@1.3.0
  cpe purl-to-cpe pkg:maven/org.apache.logging.log4j/log4j-core@2.14`,
	Args: cobra.ExactArgs(1),
	RunE: runPURLToCPE,
}

func init() {
	rootCmd.AddCommand(cpeToPurlCmd)
	rootCmd.AddCommand(purlToCpeCmd)
}

func runCPEToPURL(cmd *cobra.Command, args []string) error {
	cpe, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse CPE: %w", err)
	}

	purl, confidence, err := cpeskills.CPEToPURL(cpe)
	if err != nil {
		return fmt.Errorf("convert CPE to PURL: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"cpe":        cpe.GetURI(),
			"purl":       purl.String(),
			"confidence": confidence,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "PURL: %s\n", purl.String())
	fmt.Fprintf(cmd.OutOrStdout(), "Confidence: %.2f\n", confidence)
	return nil
}

func runPURLToCPE(cmd *cobra.Command, args []string) error {
	purl, err := cpeskills.ParsePURL(args[0])
	if err != nil {
		return fmt.Errorf("parse PURL: %w", err)
	}

	cpe, confidence, err := cpeskills.PURLToCPE(purl)
	if err != nil {
		return fmt.Errorf("convert PURL to CPE: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"purl":       purl.String(),
			"cpe":        cpe.GetURI(),
			"confidence": confidence,
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "CPE: %s\n", cpe.GetURI())
	fmt.Fprintf(cmd.OutOrStdout(), "Confidence: %.2f\n", confidence)
	return nil
}
