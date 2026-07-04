package main

import (
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// validate.go — `cpe validate <cpe>` → cpeskills.ValidateCPE (validation.go:160)
// 校验 CPE 结构是否合法：part 必为 a/h/o/*、vendor/product 非空、各字段字符合法。
// 与 mcp serve 的 validate_cpe 工具同源，但本命令走 cobra 直接暴露给命令行。

var validateCmd = &cobra.Command{
	Use:   "validate <cpe-string>",
	Short: "Validate a CPE string and report any issues",
	Long: `Parse and validate a CPE 2.2 or 2.3 string. Reports whether the CPE
is structurally valid and, if not, which check failed (part, vendor,
product, component characters).

Exits with code 0 if valid, non-zero otherwise — handy for CI gates
and shell pipelines.

Examples:
  cpe validate "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe validate -o json "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe validate "cpe:/a:apache:log4j:2.0"`,
	Args: cobra.ExactArgs(1),
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	c, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	verr := cpeskills.ValidateCPE(c)
	valid := verr == nil

	if outputFormat == "json" {
		if valid {
			fmt.Printf(`{"valid": true, "cpe": "%s"}`, c.GetURI())
		} else {
			fmt.Printf(`{"valid": false, "cpe": "%s", "error": "%s"}`, c.GetURI(), verr.Error())
		}
		fmt.Println()
		return nil
	}

	if valid {
		fmt.Fprintf(cmd.OutOrStdout(), "VALID: %s\n", c.GetURI())
		return nil
	}
	// 校验失败：把错误返回给 root 以非零退出码退出
	return fmt.Errorf("INVALID: %s — %v", c.GetURI(), verr)
}
