package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"
	"github.com/spf13/cobra"
)

// sbom.go — `cpe sbom` parent + subcommands:
//   - `cpe sbom parse --cyclonedx file.json` → ParseCycloneDXJSON
//   - `cpe sbom parse --spdx file.json` → ParseSPDXJSON
//   - `cpe sbom from-manifest <file>` → BuildSBOMFromManifest
//   - `cpe sbom export --cyclonedx sbom.json -o out.cdx.json` → 加载 + ToCycloneDXJSON
//   - `cpe sbom export --spdx sbom.json -o out.spdx.json` → ToSPDXJSON
//   - `cpe sbom diff old.json new.json` → DiffSBOMs
//   - `cpe sbom validate file.json` → ValidateSBOM
// 注意：ParseCycloneDXJSON/ParseSPDXJSON 接收 []byte，需先读取文件内容。

var (
	sbomCycloneDX bool
	sbomSPDX      bool
	sbomOutFile   string
	sbomFormat    string
)

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Software Bill of Materials (SBOM) operations",
	Long: `Parse, validate, export, and diff SBOM documents.

Supported formats: CycloneDX JSON, SPDX JSON.

Subcommands:
  sbom parse --cyclonedx/--spdx <file>  Parse SBOM file
  sbom from-manifest <file>             Build SBOM from manifest (go.mod, etc.)
  sbom export --cyclonedx/--spdx <sbom.json> -o <output>  Export SBOM to format
  sbom diff <old.json> <new.json>       Diff two SBOMs
  sbom validate <file.json>             Validate SBOM structure

Examples:
  cpe sbom parse --cycloneDX bom.json
  cpe sbom parse --spdx spdx.json -o json
  cpe sbom from-manifest go.mod
  cpe sbom export --cyclonedx sbom.json -o out.cdx.json
  cpe sbom diff old.json new.json
  cpe sbom validate bom.json`,
}

var sbomParseCmd = &cobra.Command{
	Use:   "parse <file>",
	Short: "Parse a SBOM file (CycloneDX or SPDX)",
	Args:  cobra.ExactArgs(1),
	RunE:  runSBOMParse,
}

var sbomFromManifestCmd = &cobra.Command{
	Use:   "from-manifest <file>",
	Short: "Build SBOM from a manifest file (go.mod, package.json, etc.)",
	Args:  cobra.ExactArgs(1),
	RunE:  runSBOMFromManifest,
}

var sbomExportCmd = &cobra.Command{
	Use:   "export <sbom-json-file>",
	Short: "Export SBOM to CycloneDX or SPDX format",
	Args:  cobra.ExactArgs(1),
	RunE:  runSBOMExport,
}

var sbomDiffCmd = &cobra.Command{
	Use:   "diff <old.json> <new.json>",
	Short: "Diff two SBOM JSON files",
	Args:  cobra.ExactArgs(2),
	RunE:  runSBOMDiff,
}

var sbomValidateCmd = &cobra.Command{
	Use:   "validate <file.json>",
	Short: "Validate SBOM structure",
	Args:  cobra.ExactArgs(1),
	RunE:  runSBOMValidate,
}

func init() {
	sbomParseCmd.Flags().BoolVar(&sbomCycloneDX, "cyclonedx", false, "Parse as CycloneDX JSON")
	sbomParseCmd.Flags().BoolVar(&sbomSPDX, "spdx", false, "Parse as SPDX JSON")

	sbomExportCmd.Flags().BoolVar(&sbomCycloneDX, "cyclonedx", false, "Export to CycloneDX JSON")
	sbomExportCmd.Flags().BoolVar(&sbomSPDX, "spdx", false, "Export to SPDX JSON")
	sbomExportCmd.Flags().StringVarP(&sbomOutFile, "output", "o", "", "Output file path (default stdout)")

	sbomCmd.AddCommand(sbomParseCmd)
	sbomCmd.AddCommand(sbomFromManifestCmd)
	sbomCmd.AddCommand(sbomExportCmd)
	sbomCmd.AddCommand(sbomDiffCmd)
	sbomCmd.AddCommand(sbomValidateCmd)
	rootCmd.AddCommand(sbomCmd)
}

func runSBOMParse(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var sbom *cpeskills.SBOM
	if sbomCycloneDX {
		sbom, err = cpeskills.ParseCycloneDXJSON(data)
	} else if sbomSPDX {
		sbom, err = cpeskills.ParseSPDXJSON(data)
	} else {
		return fmt.Errorf("must specify --cyclonedx or --spdx")
	}
	if err != nil {
		return fmt.Errorf("parse SBOM: %w", err)
	}

	if outputFormat == "json" {
		return outputSBOMJSON(cmd, sbom)
	}

	// text 格式
	fmt.Fprintf(cmd.OutOrStdout(), "SBOM: %s\n", sbom.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "  Components: %d\n", sbom.ComponentCount())
	for _, comp := range sbom.Components {
		fmt.Fprintf(cmd.OutOrStdout(), "    - %s (%s)\n", comp.Name, comp.Version)
	}
	return nil
}

// outputSBOMJSON 把 SBOM 用 ToJSON 输出到 stdout
func outputSBOMJSON(cmd *cobra.Command, sbom *cpeskills.SBOM) error {
	data, err := sbom.ToJSON()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func runSBOMFromManifest(cmd *cobra.Command, args []string) error {
	filename := args[0]
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	sbom, err := cpeskills.BuildSBOMFromManifest(filename, string(content), filename)
	if err != nil {
		return fmt.Errorf("build SBOM from manifest: %w", err)
	}

	if outputFormat == "json" {
		return outputSBOMJSON(cmd, sbom)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "SBOM from %s:\n", filename)
	fmt.Fprintf(cmd.OutOrStdout(), "  Components: %d\n", sbom.ComponentCount())
	for _, comp := range sbom.Components {
		fmt.Fprintf(cmd.OutOrStdout(), "    - %s (%s)\n", comp.Name, comp.Version)
	}
	return nil
}

func runSBOMExport(cmd *cobra.Command, args []string) error {
	// 先从 JSON 加载 SBOM（用 ToJSON 输出的格式）
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var sbom cpeskills.SBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("parse SBOM JSON: %w", err)
	}

	var outData []byte
	if sbomCycloneDX {
		outData, err = sbom.ToCycloneDXJSON()
	} else if sbomSPDX {
		outData, err = sbom.ToSPDXJSON()
	} else {
		return fmt.Errorf("must specify --cyclonedx or --spdx")
	}
	if err != nil {
		return fmt.Errorf("export SBOM: %w", err)
	}

	if sbomOutFile != "" {
		return os.WriteFile(sbomOutFile, outData, 0644)
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(outData))
	return nil
}

func runSBOMDiff(cmd *cobra.Command, args []string) error {
	oldData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read old SBOM: %w", err)
	}
	newData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("read new SBOM: %w", err)
	}

	// 先解析为 SBOM（通过 ToJSON 格式）
	var oldSBOM, newSBOM cpeskills.SBOM
	if err := json.Unmarshal(oldData, &oldSBOM); err != nil {
		// 尝试 CycloneDX
		tmp, err2 := cpeskills.ParseCycloneDXJSON(oldData)
		if err2 != nil {
			return fmt.Errorf("parse old SBOM: %w", err)
		}
		oldSBOM = *tmp
	}
	if err := json.Unmarshal(newData, &newSBOM); err != nil {
		tmp, err2 := cpeskills.ParseCycloneDXJSON(newData)
		if err2 != nil {
			return fmt.Errorf("parse new SBOM: %w", err)
		}
		newSBOM = *tmp
	}

	diff := cpeskills.DiffSBOMs(&oldSBOM, &newSBOM)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "SBOM Diff:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Added:    %d components\n", len(diff.Added))
	fmt.Fprintf(cmd.OutOrStdout(), "  Removed:  %d components\n", len(diff.Removed))
	fmt.Fprintf(cmd.OutOrStdout(), "  Changed:  %d components\n", len(diff.Changed))
	fmt.Fprintf(cmd.OutOrStdout(), "  Unchanged: %d components\n", diff.Unchanged)
	return nil
}

func runSBOMValidate(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// 尝试多种格式
	var sbom *cpeskills.SBOM
	sbom, err = cpeskills.ParseCycloneDXJSON(data)
	if err != nil {
		sbom, err = cpeskills.ParseSPDXJSON(data)
		if err != nil {
			// 尝试 ToJSON 格式
			var tmp cpeskills.SBOM
			if json.Unmarshal(data, &tmp) != nil {
				return fmt.Errorf("parse SBOM: cannot parse as CycloneDX, SPDX, or internal JSON")
			}
			sbom = &tmp
		}
	}

	issues := cpeskills.ValidateSBOM(sbom)

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]interface{}{
			"valid":  len(issues) == 0,
			"issues": issues,
		})
	}

	if len(issues) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "VALID: %s\n", args[0])
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "INVALID: %s (%d issues)\n", args[0], len(issues))
	for _, issue := range issues {
		fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", issue)
	}
	return fmt.Errorf("validation failed")
}
