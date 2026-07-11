package main

import (
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// vex.go — `cpe vex` parent + subcommands:
//   - `cpe vex parse <file.json>` → ParseVEXDocument
//   - `cpe vex build --product ... --cve ... --status ... --justification ...` → NewVEXDocument + AddStatement + ToJSON
// VEX (Vulnerability Exploitability eXchange) 是 CSAF 的可利用性声明格式。

var (
	vexProduct       string
	vexProductID     string
	vexAuthor        string
	vexCVE           string
	vexStatus        string
	vexJustification string
)

var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "Vulnerability Exploitability eXchange (VEX) operations",
	Long: `Parse and build VEX documents.

VEX statements declare whether a product is affected by a given vulnerability.

Subcommands:
  vex parse <file.json>   Parse a VEX document
  vex build               Build a VEX document from flags

Status values: not_affected, affected, fixed, under_investigation

Examples:
  cpe vex parse vex.json
  cpe vex build --product "MyApp" --cve CVE-2021-44228 --status not_affected \\
    --justification component_not_present
  cpe vex build -o json --product "MyApp" --cve CVE-2021-44228 --status affected`,
}

var vexParseCmd = &cobra.Command{
	Use:   "parse <file.json>",
	Short: "Parse a VEX document",
	Args:  cobra.ExactArgs(1),
	RunE:  runVEXParse,
}

var vexBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build a VEX document from flags",
	RunE:  runVEXBuild,
}

func init() {
	vexBuildCmd.Flags().StringVar(&vexProduct, "product", "", "Product name")
	vexBuildCmd.Flags().StringVar(&vexProductID, "product-id", "", "Product ID")
	vexBuildCmd.Flags().StringVar(&vexAuthor, "author", "cpe-cli", "Author/issuer")
	vexBuildCmd.Flags().StringVar(&vexCVE, "cve", "", "Vulnerability ID (CVE)")
	vexBuildCmd.Flags().StringVar(&vexStatus, "status", "not_affected", "Status: not_affected, affected, fixed, under_investigation")
	vexBuildCmd.Flags().StringVar(&vexJustification, "justification", "", "Justification (e.g., component_not_present)")
	vexBuildCmd.MarkFlagRequired("product")
	vexBuildCmd.MarkFlagRequired("cve")

	vexCmd.AddCommand(vexParseCmd)
	vexCmd.AddCommand(vexBuildCmd)
	rootCmd.AddCommand(vexCmd)
}

func runVEXParse(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	doc, err := cpeskills.ParseVEXDocument(data)
	if err != nil {
		return fmt.Errorf("parse VEX: %w", err)
	}

	if outputFormat == "json" {
		out, err := doc.ToJSON()
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "VEX Document:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Product: %s\n", doc.ProductName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Statements: %d\n", doc.StatementCount())
	for _, stmt := range doc.Statements {
		fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", stmt.VulnerabilityID, stmt.Status)
	}
	return nil
}

func runVEXBuild(cmd *cobra.Command, args []string) error {
	productID := vexProductID
	if productID == "" {
		productID = vexProduct
	}

	doc := cpeskills.NewVEXDocument("cyclonedx", productID, vexProduct, vexAuthor)
	stmt := cpeskills.NewVEXStatement(vexCVE, productID, cpeskills.VEXStatus(vexStatus))
	if vexJustification != "" {
		stmt.Justification = cpeskills.VEXJustification(vexJustification)
	}
	doc.AddStatement(stmt)

	out, err := doc.ToJSON()
	if err != nil {
		return fmt.Errorf("serialize VEX: %w", err)
	}

	if outputFormat == "json" || outputFormat == "" {
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	// text 格式：摘要
	fmt.Fprintf(cmd.OutOrStdout(), "Built VEX document:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Product: %s (id=%s)\n", vexProduct, productID)
	fmt.Fprintf(cmd.OutOrStdout(), "  Author:  %s\n", vexAuthor)
	fmt.Fprintf(cmd.OutOrStdout(), "  Statements: %d\n", doc.StatementCount())
	fmt.Fprintf(cmd.OutOrStdout(), "    - %s: %s\n", vexCVE, vexStatus)
	return nil
}
