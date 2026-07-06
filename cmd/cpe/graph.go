package main

import (
	"encoding/json"
	"fmt"
	"os"

	cpeskills "github.com/scagogogo/cpe-skills"
	"github.com/spf13/cobra"
)

// graph.go — `cpe graph topo --sbom sbom.json` → 从 SBOM 建 DependencyGraph + TopologicalSort
//            `cpe graph build --sbom sbom.json` → NewDependencyGraph + AddComponent 循环
// 依赖图：从 SBOM 构件依赖关系图，支持拓扑排序、路径查询等。

var graphSBOMFile string

var graphCmd = &cobra.Command{
	Use:   "graph",
	Short: "Dependency graph operations",
	Long: `Build and analyze dependency graphs from SBOMs.

Subcommands:
  graph build --sbom <file>  Build a dependency graph from SBOM
  graph topo --sbom <file>   Topological sort of dependencies

Examples:
  cpe graph build --sbom sbom.json
  cpe graph topo --sbom sbom.json
  cpe graph topo -o json --sbom sbom.json`,
}

var graphBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build dependency graph from SBOM",
	RunE:  runGraphBuild,
}

var graphTopoCmd = &cobra.Command{
	Use:   "topo",
	Short: "Topological sort of dependencies",
	RunE:  runGraphTopo,
}

func init() {
	for _, cmd := range []*cobra.Command{graphBuildCmd, graphTopoCmd} {
		cmd.Flags().StringVar(&graphSBOMFile, "sbom", "", "SBOM JSON file")
		cmd.MarkFlagRequired("sbom")
	}

	graphCmd.AddCommand(graphBuildCmd)
	graphCmd.AddCommand(graphTopoCmd)
	rootCmd.AddCommand(graphCmd)
}

func loadSBOMGraph(path string) (*cpeskills.DependencyGraph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sbom cpeskills.SBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return nil, err
	}

	graph := cpeskills.NewDependencyGraph()
	for _, comp := range sbom.Components {
		graph.AddNode(comp)
	}
	for _, dep := range sbom.Dependencies {
		for _, dependsOn := range dep.DependsOn {
			graph.AddEdge(dep.Ref, dependsOn)
		}
	}
	return graph, nil
}

func runGraphBuild(cmd *cobra.Command, args []string) error {
	graph, err := loadSBOMGraph(graphSBOMFile)
	if err != nil {
		return fmt.Errorf("load SBOM graph: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]int{
			"nodes": graph.NodeCount(),
		})
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Dependency Graph:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Nodes: %d\n", graph.NodeCount())
	return nil
}

func runGraphTopo(cmd *cobra.Command, args []string) error {
	graph, err := loadSBOMGraph(graphSBOMFile)
	if err != nil {
		return fmt.Errorf("load SBOM graph: %w", err)
	}

	nodes, err := graph.TopologicalSort()
	if err != nil {
		return fmt.Errorf("topological sort: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		names := make([]string, len(nodes))
		for i, n := range nodes {
			if n.Component != nil {
				names[i] = n.Component.Name
			} else {
				names[i] = n.ID
			}
		}
		return enc.Encode(names)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Topological Sort (%d nodes):\n", len(nodes))
	for _, n := range nodes {
		if n.Component != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s (%s)\n", n.Component.Name, n.Component.Version)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", n.ID)
		}
	}
	return nil
}
