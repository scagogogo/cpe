package main

import (
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// generate.go — `cpe generate --part a --vendor ... --product ... --version ...`
// → cpeskills.GenerateCPE (generator.go:10)
// 可选 --fill-defaults 调 cpeskills.FillDefaults (generator.go:37)
// 与 mcp serve 的 generate_cpe 工具同源，但本命令走 cobra 直接暴露。

var (
	genPart         string
	genVendor       string
	genProduct      string
	genVersion      string
	genFillDefaults bool
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a CPE string from components",
	Long: `Build a CPE 2.3 string from the four core components: part, vendor,
product, and version. Empty fields are left as ANY (*) unless
--fill-defaults is given.

Part must be one of: a, h, o (or the long forms: application,
hardware, operating-system).

Examples:
  cpe generate --part a --vendor microsoft --product windows --version 10
  cpe generate --part o --vendor linux --product kernel --version 5.15
  cpe generate --part h --vendor dell --product poweredge_r740 --version ""
  cpe generate -o json --part a --vendor apache --product log4j --version 2.14`,
	RunE: runGenerate,
}

func init() {
	generateCmd.Flags().StringVarP(&genPart, "part", "p", "", "CPE part: a (application), h (hardware), o (operating system)")
	generateCmd.Flags().StringVarP(&genVendor, "vendor", "v", "", "Vendor name")
	generateCmd.Flags().StringVarP(&genProduct, "product", "r", "", "Product name")
	generateCmd.Flags().StringVarP(&genVersion, "version", "V", "", "Version string")
	generateCmd.Flags().BoolVar(&genFillDefaults, "fill-defaults", false, "Fill empty fields with ANY (*)")

	generateCmd.MarkFlagRequired("part")
	generateCmd.MarkFlagRequired("vendor")
	generateCmd.MarkFlagRequired("product")

	rootCmd.AddCommand(generateCmd)
}

func runGenerate(cmd *cobra.Command, args []string) error {
	c := cpeskills.GenerateCPE(genPart, genVendor, genProduct, genVersion)
	if genFillDefaults {
		c = cpeskills.FillDefaults(c)
	}

	// 校验生成的 CPE 是否合法
	if err := cpeskills.ValidateCPE(c); err != nil {
		return fmt.Errorf("generated CPE is invalid: %w", err)
	}

	if outputFormat == "json" {
		return outputCPE(cmd.OutOrStdout(), c, "json")
	}
	fmt.Println(c.GetURI())
	return nil
}
