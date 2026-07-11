package cpeskills

import (
	"fmt"
	"strings"
)

// ReachabilityLevel describes how directly a vulnerability can be reached.
type ReachabilityLevel string

const (
	// ReachabilityDirect the vulnerability is in a directly-used API
	ReachabilityDirect ReachabilityLevel = "direct"

	// ReachabilityTransitive the vulnerability is in a transitive dependency
	ReachabilityTransitive ReachabilityLevel = "transitive"

	// ReachabilityConditional the vulnerability is reachable only under certain conditions
	ReachabilityConditional ReachabilityLevel = "conditional"

	// ReachabilityNotReachable the vulnerability cannot be reached
	ReachabilityNotReachable ReachabilityLevel = "not_reachable"

	// ReachabilityUnknown reachability cannot be determined
	ReachabilityUnknown ReachabilityLevel = "unknown"
)

// ReachabilityResult describes the reachability analysis result for a single vulnerability.
type ReachabilityResult struct {
	// Vulnerability is the vulnerability finding being analyzed
	Vulnerability *VulnerabilityFinding `json:"vulnerability"`

	// Level is the reachability assessment
	Level ReachabilityLevel `json:"level"`

	// Path is the call/dependency path from root to the vulnerable component
	Path []string `json:"path,omitempty"`

	// Evidence describes how the reachability was determined
	Evidence string `json:"evidence,omitempty"`

	// Confidence is the confidence in the reachability assessment (0.0-1.0)
	Confidence float64 `json:"confidence"`
}

// ReachabilityAnalyzer analyzes the reachability of vulnerabilities in a dependency graph.
//
// This interface allows for pluggable reachability analysis implementations,
// from simple dependency-graph traversal to full static analysis.
type ReachabilityAnalyzer interface {
	// Analyze analyzes reachability for all findings against a dependency graph.
	Analyze(graph *DependencyGraph, findings []*VulnerabilityFinding) ([]*ReachabilityResult, error)

	// AnalyzeComponent analyzes reachability for a single component.
	AnalyzeComponent(graph *DependencyGraph, component *SBOMComponent, findings []*VulnerabilityFinding) ([]*ReachabilityResult, error)
}

// DependencyGraphReachabilityAnalyzer uses dependency graph depth to determine reachability.
//
// This is the default, lightweight analyzer suitable for most SCA use cases.
// It determines reachability based on whether a component is a direct or transitive dependency.
type DependencyGraphReachabilityAnalyzer struct {
	// MaxDepth is the maximum dependency depth to analyze (0 = unlimited)
	MaxDepth int

	// IncludeDevDependencies includes development dependencies in analysis
	IncludeDevDependencies bool
}

// NewDependencyGraphReachabilityAnalyzer creates a default dependency graph reachability analyzer.
func NewDependencyGraphReachabilityAnalyzer() *DependencyGraphReachabilityAnalyzer {
	return &DependencyGraphReachabilityAnalyzer{
		MaxDepth:               0, // unlimited
		IncludeDevDependencies: false,
	}
}

// Analyze analyzes reachability for all findings against a dependency graph.
func (a *DependencyGraphReachabilityAnalyzer) Analyze(graph *DependencyGraph, findings []*VulnerabilityFinding) ([]*ReachabilityResult, error) {
	if graph == nil {
		return nil, fmt.Errorf("dependency graph is nil")
	}

	// Ensure depths are computed
	graph.ComputeDepths()

	results := make([]*ReachabilityResult, 0, len(findings))

	for _, finding := range findings {
		result := &ReachabilityResult{
			Vulnerability: finding,
			Confidence:    0.7, // base confidence for graph-based analysis
		}

		// Default to unknown
		result.Level = ReachabilityUnknown

		// Walk through all nodes to find which component this finding belongs to
		for _, node := range graph.Nodes {
			if node.Component == nil {
				continue
			}

			// Match by CVE CPE if available
			if finding.CVE != nil && node.Component.CPE != nil {
				if finding.CVE.CVEID == node.Component.CPE.Cve ||
					containsCPE(finding.CVE.AffectedCPEs, node.Component.CPE.Cpe23) {
					result = a.assessNode(graph, node, finding)
					break
				}
			}

			// Match by PURL
			if finding.OSV != nil && node.Component.PURL != nil {
				for _, affected := range finding.OSV.Affected {
					if affected.Package != nil &&
						affected.Package.Name == node.Component.PURL.FullName() {
						result = a.assessNode(graph, node, finding)
						break
					}
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// AnalyzeComponent analyzes reachability for a single component.
func (a *DependencyGraphReachabilityAnalyzer) AnalyzeComponent(graph *DependencyGraph, component *SBOMComponent, findings []*VulnerabilityFinding) ([]*ReachabilityResult, error) {
	if graph == nil {
		return nil, fmt.Errorf("dependency graph is nil")
	}

	// Find the node for this component
	var targetNode *DependencyNode
	for _, node := range graph.Nodes {
		if node.Component == component {
			targetNode = node
			break
		}
	}

	if targetNode == nil {
		return nil, fmt.Errorf("component not found in dependency graph")
	}

	results := make([]*ReachabilityResult, 0, len(findings))
	for _, finding := range findings {
		result := a.assessNode(graph, targetNode, finding)
		results = append(results, result)
	}

	return results, nil
}

// assessNode evaluates reachability for a specific node.
func (a *DependencyGraphReachabilityAnalyzer) assessNode(graph *DependencyGraph, node *DependencyNode, finding *VulnerabilityFinding) *ReachabilityResult {
	result := &ReachabilityResult{
		Vulnerability: finding,
		Path:         make([]string, 0),
	}

	if node.Direct {
		result.Level = ReachabilityDirect
		result.Evidence = fmt.Sprintf("Component %s is a direct dependency (depth %d)", node.Component.Name, node.Depth)
		result.Confidence = 0.9
	} else {
		result.Level = ReachabilityTransitive
		result.Evidence = fmt.Sprintf("Component %s is a transitive dependency (depth %d)", node.Component.Name, node.Depth)
		result.Confidence = 0.8

		// Try to find the path from root dependencies
		directDeps := graph.GetDirectDependencies()
		for _, direct := range directDeps {
			if path, err := graph.GetDependencyPath(direct.ID, node.ID); err == nil {
				result.Path = path
				result.Evidence += fmt.Sprintf("\nPath: %s", strings.Join(path, " → "))
				break
			}
		}
	}

	// Apply depth limit
	if a.MaxDepth > 0 && node.Depth > a.MaxDepth {
		result.Level = ReachabilityNotReachable
		result.Evidence = fmt.Sprintf("Component exceeds max depth of %d", a.MaxDepth)
		result.Confidence = 0.6
	}

	// Update finding with reachability info
	finding.Reachability = string(result.Level)

	return result
}

// containsCPE checks if a CPE URI is in the list of affected CPEs.
func containsCPE(cpes []string, target string) bool {
	for _, c := range cpes {
		if c == target {
			return true
		}
	}
	return false
}

// QuickReachabilityCheck is a convenience function for quick reachability assessment.
//
// Uses the dependency graph analyzer with default settings.
func QuickReachabilityCheck(graph *DependencyGraph, component *SBOMComponent, finding *VulnerabilityFinding) *ReachabilityResult {
	analyzer := NewDependencyGraphReachabilityAnalyzer()
	results, _ := analyzer.AnalyzeComponent(graph, component, []*VulnerabilityFinding{finding})
	if len(results) > 0 {
		return results[0]
	}
	return &ReachabilityResult{
		Vulnerability: finding,
		Level:        ReachabilityUnknown,
		Confidence:    0.0,
	}
}

// BatchReachabilityAnalysis performs reachability analysis on multiple dependency graphs.
//
// Useful for monorepo scenarios where each sub-project has its own dependency graph.
func BatchReachabilityAnalysis(graphs []*DependencyGraph, findings []*VulnerabilityFinding) (map[string][]*ReachabilityResult, error) {
	analyzer := NewDependencyGraphReachabilityAnalyzer()
	results := make(map[string][]*ReachabilityResult)

	for i, graph := range graphs {
		key := fmt.Sprintf("graph-%d", i)
		if graph != nil && len(graph.Nodes) > 0 {
			// Find the project name from root nodes
			for _, node := range graph.Nodes {
				if node.Direct && node.Component != nil && node.Component.Name != "" {
					key = node.Component.Name
					break
				}
			}
		}

		r, err := analyzer.Analyze(graph, findings)
		if err != nil {
			results[key] = nil
			continue
		}
		results[key] = r
	}

	return results, nil
}

// ReachabilitySummary generates a summary of reachability analysis results.
type ReachabilitySummary struct {
	// Total total vulnerabilities analyzed
	Total int `json:"total"`

	// Direct count of directly reachable vulnerabilities
	Direct int `json:"direct"`

	// Transitive count of transitively reachable vulnerabilities
	Transitive int `json:"transitive"`

	// Conditional count of conditionally reachable vulnerabilities
	Conditional int `json:"conditional"`

	// NotReachable count of unreachable vulnerabilities
	NotReachable int `json:"notReachable"`

	// Unknown count of vulnerabilities with unknown reachability
	Unknown int `json:"unknown"`

	// HighestRiskLevel the highest risk reachability level with count > 0
	HighestRiskLevel string `json:"highestRiskLevel"`
}

// SummarizeReachability generates a summary from reachability results.
func SummarizeReachability(results []*ReachabilityResult) *ReachabilitySummary {
	summary := &ReachabilitySummary{
		Total: len(results),
	}

	for _, r := range results {
		switch r.Level {
		case ReachabilityDirect:
			summary.Direct++
		case ReachabilityTransitive:
			summary.Transitive++
		case ReachabilityConditional:
			summary.Conditional++
		case ReachabilityNotReachable:
			summary.NotReachable++
		default:
			summary.Unknown++
		}
	}

	// Determine highest risk level
	if summary.Direct > 0 {
		summary.HighestRiskLevel = string(ReachabilityDirect)
	} else if summary.Transitive > 0 {
		summary.HighestRiskLevel = string(ReachabilityTransitive)
	} else if summary.Conditional > 0 {
		summary.HighestRiskLevel = string(ReachabilityConditional)
	} else {
		summary.HighestRiskLevel = string(ReachabilityUnknown)
	}

	return summary
}

// GetActionableFindings filters findings to those that are reachable.
//
// Excludes findings with NotReachable or Unknown reachability levels.
func GetActionableFindings(results []*ReachabilityResult) []*VulnerabilityFinding {
	var actionable []*VulnerabilityFinding
	for _, r := range results {
		if r.Level != ReachabilityNotReachable {
			actionable = append(actionable, r.Vulnerability)
		}
	}
	return actionable
}
