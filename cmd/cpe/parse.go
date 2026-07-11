package main

import (
	"fmt"
	"io"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

var parseFormat string

var parseCmd = &cobra.Command{
	Use:   "parse <cpe-string>",
	Short: "Parse a CPE string and display its components",
	Long: `Parse a CPE 2.2 or 2.3 formatted string and display
its individual components (part, vendor, product, version, etc.).

The command automatically detects whether the input is CPE 2.2
(starts with "cpe:/") or CPE 2.3 (starts with "cpe:2.3:").

Examples:
  cpe parse "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe parse "cpe:/a:apache:log4j:2.0"
  cpe parse -o json "cpe:2.3:a:oracle:java:1.8.0:291:*:*:*:*:*:*"`,
	Args: cobra.ExactArgs(1),
	RunE: runParse,
}

func init() {
	parseCmd.Flags().StringVarP(&parseFormat, "to", "t", "", "Convert to format (2.2|2.3|wfn)")
	rootCmd.AddCommand(parseCmd)
}

func runParse(cmd *cobra.Command, args []string) error {
	input := args[0]
	c, err := parseCPEString(input)
	if err != nil {
		return err
	}

	// 如果指定了转换格式，先输出转换结果
	if parseFormat != "" {
		return outputConversion(cmd.OutOrStdout(), c, parseFormat)
	}

	return outputCPE(cmd.OutOrStdout(), c, outputFormat)
}

// parseCPEString 自动检测 CPE 版本并解析
func parseCPEString(input string) (*cpeskills.CPE, error) {
	if len(input) >= 6 && input[:6] == "cpe:2." {
		return cpeskills.ParseCpe23(input)
	}
	if len(input) >= 5 && input[:5] == "cpe:/" {
		return cpeskills.ParseCpe22(input)
	}
	return nil, fmt.Errorf("unrecognized CPE format: %s (expected CPE 2.2 or 2.3)", input)
}

// outputConversion 输出格式转换结果
func outputConversion(w io.Writer, c *cpeskills.CPE, format string) error {
	switch format {
	case "2.2":
		fmt.Fprintln(w, cpeskills.FormatCpe22(c))
	case "2.3":
		fmt.Fprintln(w, cpeskills.FormatCpe23(c))
	case "wfn":
		wfn := cpeskills.FromCPE(c)
		fmt.Fprintf(w, "wfn:[part=%s,vendor=%s,product=%s,version=%s,update=%s,edition=%s,language=%s]\n",
			wfn.Part, wfn.Vendor, wfn.Product, wfn.Version, wfn.Update, wfn.Edition, wfn.Language)
	default:
		return fmt.Errorf("unsupported conversion format: %s (supported: 2.2, 2.3, wfn)", format)
	}
	return nil
}
