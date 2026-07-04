package main

import (
	"encoding/json"
	"fmt"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// wfn.go — WFN (Well-Formed Name) 绑定转换：
//   - `cpe wfn to-fs <cpe>` → FromCPE + BindToFS
//   - `cpe wfn to-uri <cpe>` → FromCPE + BindToURI
//   - `cpe wfn from-fs <fs>` → UnbindFS
//   - `cpe wfn from-uri <uri>` → UnbindURI
// WFN 是 NISTIR 7695 定义的 CPE 内部规范化表示。

var wfnCmd = &cobra.Command{
	Use:   "wfn",
	Short: "Well-Formed Name (WFN) binding operations",
	Long: `Convert between CPE and WFN (Well-Formed Name) bindings.

WFN is the internal normalized form per NISTIR 7695. Bindings:
  - FS  (Formatted String) — used in CPE 2.3
  - URI — used in CPE 2.2

Subcommands:
  wfn to-fs <cpe>    CPE → WFN → Formatted String
  wfn to-uri <cpe>   CPE → WFN → URI binding
  wfn from-fs <fs>   Formatted String → WFN
  wfn from-uri <uri> URI → WFN

Examples:
  cpe wfn to-fs "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
  cpe wfn to-uri "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe wfn from-fs "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"`,
}

var wfnToFSCmd = &cobra.Command{
	Use:   "to-fs <cpe-string>",
	Short: "Convert CPE to WFN Formatted String binding",
	Args:  cobra.ExactArgs(1),
	RunE:  runWFNToFS,
}

var wfnToURICmd = &cobra.Command{
	Use:   "to-uri <cpe-string>",
	Short: "Convert CPE to WFN URI binding",
	Args:  cobra.ExactArgs(1),
	RunE:  runWFNToURI,
}

var wfnFromFSCmd = &cobra.Command{
	Use:   "from-fs <formatted-string>",
	Short: "Convert WFN Formatted String to WFN",
	Args:  cobra.ExactArgs(1),
	RunE:  runWFNFromFS,
}

var wfnFromURICmd = &cobra.Command{
	Use:   "from-uri <uri>",
	Short: "Convert WFN URI binding to WFN",
	Args:  cobra.ExactArgs(1),
	RunE:  runWFNFromURI,
}

func init() {
	wfnCmd.AddCommand(wfnToFSCmd)
	wfnCmd.AddCommand(wfnToURICmd)
	wfnCmd.AddCommand(wfnFromFSCmd)
	wfnCmd.AddCommand(wfnFromURICmd)
	rootCmd.AddCommand(wfnCmd)
}

func runWFNToFS(cmd *cobra.Command, args []string) error {
	cpe, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse CPE: %w", err)
	}

	w := cpeskills.FromCPE(cpe)
	fs := cpeskills.BindToFS(w)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"input": cpe.GetURI(),
			"fs":    fs,
		})
	}

	fmt.Fprintln(cmd.OutOrStdout(), fs)
	return nil
}

func runWFNToURI(cmd *cobra.Command, args []string) error {
	cpe, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parse CPE: %w", err)
	}

	w := cpeskills.FromCPE(cpe)
	uri := cpeskills.BindToURI(w)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{
			"input": cpe.GetURI(),
			"uri":   uri,
		})
	}

	fmt.Fprintln(cmd.OutOrStdout(), uri)
	return nil
}

func runWFNFromFS(cmd *cobra.Command, args []string) error {
	w, err := cpeskills.UnbindFS(args[0])
	if err != nil {
		return fmt.Errorf("unbind FS: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(w)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "WFN:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Part:    %s\n", w.Part)
	fmt.Fprintf(cmd.OutOrStdout(), "  Vendor:  %s\n", w.Vendor)
	fmt.Fprintf(cmd.OutOrStdout(), "  Product: %s\n", w.Product)
	fmt.Fprintf(cmd.OutOrStdout(), "  Version: %s\n", w.Version)
	return nil
}

func runWFNFromURI(cmd *cobra.Command, args []string) error {
	w, err := cpeskills.UnbindURI(args[0])
	if err != nil {
		return fmt.Errorf("unbind URI: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(w)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "WFN:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Part:    %s\n", w.Part)
	fmt.Fprintf(cmd.OutOrStdout(), "  Vendor:  %s\n", w.Vendor)
	fmt.Fprintf(cmd.OutOrStdout(), "  Product: %s\n", w.Product)
	fmt.Fprintf(cmd.OutOrStdout(), "  Version: %s\n", w.Version)
	return nil
}