package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// relation.go — `cpe relation <a> <b>` → CPE.CompareTo (cpe.go:381)
// 输出 equal/subset/superset/disjoint/overlap/unknown。
// 用于判断两个 CPE 的集合关系，是 NISTIR 7696 匹配逻辑的核心。

var relationCmd = &cobra.Command{
	Use:   "relation <criteria-cpe> <target-cpe>",
	Short: "Determine the relation between two CPEs",
	Long: `Compare two CPE strings and output the matching relation
(one of: equal, subset, superset, disjoint, overlap, unknown).

The first argument is the criteria (source), the second is the target.
Relation semantics follow NISTIR 7696:
  - equal: same vendor/product/version (no ANY wildcard diff)
  - subset: criteria is narrower than target (criteria has fewer ANY)
  - superset: criteria is broader than target (criteria has more ANY)
  - disjoint: no overlap
  - overlap: mixed overlap without clear hierarchy
  - unknown: cannot determine

Examples:
  cpe relation "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*" "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
  cpe relation "cpe:2.3:a:*:log4j:*:*:*:*:*:*:*" "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"
  cpe relation -o json "cpe:2.3:a:microsoft:windows:10" "cpe:2.3:a:microsoft:windows:11"`,
	Args: cobra.ExactArgs(2),
	RunE: runRelation,
}

func init() {
	rootCmd.AddCommand(relationCmd)
}

func runRelation(cmd *cobra.Command, args []string) error {
	criteria, err := parseCPEString(args[0])
	if err != nil {
		return fmt.Errorf("parsing criteria CPE: %w", err)
	}
	target, err := parseCPEString(args[1])
	if err != nil {
		return fmt.Errorf("parsing target CPE: %w", err)
	}

	rel := criteria.CompareTo(target)
	relStr := rel.String()

	if outputFormat == "json" {
		fmt.Fprintf(cmd.OutOrStdout(), `{"relation": "%s", "criteria": "%s", "target": "%s"}`+"\n", relStr, criteria.GetURI(), target.GetURI())
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%s\n", relStr)
	return nil
}
