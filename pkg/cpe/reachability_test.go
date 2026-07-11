package cpeskills

import (
	"strings"
	"testing"
)

// helper: build a simple graph with a direct dependency and a transitive dependency
//
//	root -> directDep -> transitiveDep
func buildReachabilityTestGraph() (*DependencyGraph, *SBOMComponent, *SBOMComponent, *SBOMComponent) {
	root := &SBOMComponent{BomRef: "root", Name: "root-app", Version: "1.0.0"}
	directDep := &SBOMComponent{BomRef: "direct-lib", Name: "direct-lib", Version: "2.0.0"}
	transitiveDep := &SBOMComponent{BomRef: "transitive-lib", Name: "transitive-lib", Version: "3.0.0"}

	g := NewDependencyGraph()
	g.AddComponent(root, []*SBOMComponent{directDep})

	// Mark direct-lib as a direct dependency of the root project
	if node, ok := g.Nodes["direct-lib"]; ok {
		node.Direct = true
	}

	// Add transitive edge: direct-lib -> transitive-lib
	g.AddEdge("direct-lib", "transitive-lib")
	// Mark transitive-lib as non-direct (transitive dependency)
	if node, ok := g.Nodes["transitive-lib"]; ok {
		node.Direct = false
		node.Component = transitiveDep
	}

	g.ComputeDepths()
	return g, root, directDep, transitiveDep
}

// ---------------------------------------------------------------------------
// NewDependencyGraphReachabilityAnalyzer
// ---------------------------------------------------------------------------

func TestReachability_NewAnalyzerDefaults(t *testing.T) {
	a := NewDependencyGraphReachabilityAnalyzer()
	if a.MaxDepth != 0 {
		t.Errorf("expected MaxDepth 0 (unlimited), got %d", a.MaxDepth)
	}
	if a.IncludeDevDependencies {
		t.Error("expected IncludeDevDependencies to be false by default")
	}
}

// ---------------------------------------------------------------------------
// Analyze
// ---------------------------------------------------------------------------

func TestReachability_Analyze_NilGraph_ReturnsError(t *testing.T) {
	a := NewDependencyGraphReachabilityAnalyzer()
	_, err := a.Analyze(nil, []*VulnerabilityFinding{})
	if err == nil {
		t.Fatal("expected error for nil graph, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("error should mention nil, got: %v", err)
	}
}

func TestReachability_Analyze_EmptyFindings_ReturnsEmptyResults(t *testing.T) {
	g, _, _, _ := buildReachabilityTestGraph()
	a := NewDependencyGraphReachabilityAnalyzer()

	results, err := a.Analyze(g, []*VulnerabilityFinding{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty findings, got %d", len(results))
	}
}

func TestReachability_Analyze_WithGraphAndFindings(t *testing.T) {
	g, _, _, transitiveDep := buildReachabilityTestGraph()

	// Create a finding that matches the transitive dep via CPE
	cpe, _ := Parse("cpe:2.3:a:example:transitive-lib:3.0.0:*:*:*:*:*:*:*")
	transitiveDep.CPE = cpe

	finding := &VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID: "CVE-2023-0001",
			AffectedCPEs: []string{
				"cpe:2.3:a:example:transitive-lib:3.0.0:*:*:*:*:*:*:*",
			},
		},
	}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.Analyze(g, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// The transitive dep should be classified as transitive
	if results[0].Level != ReachabilityTransitive {
		t.Errorf("expected level %q, got %q", ReachabilityTransitive, results[0].Level)
	}
	if results[0].Vulnerability != finding {
		t.Error("result should reference the original finding")
	}
}

func TestReachability_Analyze_DirectDependency(t *testing.T) {
	g, root, _, _ := buildReachabilityTestGraph()

	cpe, _ := Parse("cpe:2.3:a:example:root-app:1.0.0:*:*:*:*:*:*:*")
	root.CPE = cpe

	finding := &VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID: "CVE-2023-0002",
			AffectedCPEs: []string{
				"cpe:2.3:a:example:root-app:1.0.0:*:*:*:*:*:*:*",
			},
		},
	}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.Analyze(g, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Level != ReachabilityDirect {
		t.Errorf("expected level %q, got %q", ReachabilityDirect, results[0].Level)
	}
}

func TestReachability_Analyze_NoMatchingNode_ReturnsUnknown(t *testing.T) {
	g, _, _, _ := buildReachabilityTestGraph()

	// Finding that doesn't match any node in the graph
	finding := &VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID:       "CVE-2023-9999",
			AffectedCPEs: []string{"cpe:2.3:a:nonexistent:pkg:1.0:*:*:*:*:*:*:*"},
		},
	}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.Analyze(g, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Level != ReachabilityUnknown {
		t.Errorf("expected level %q, got %q", ReachabilityUnknown, results[0].Level)
	}
}

func TestReachability_Analyze_MaxDepthExceedsNotReachable(t *testing.T) {
	g, _, _, transitiveDep := buildReachabilityTestGraph()

	cpe, _ := Parse("cpe:2.3:a:example:transitive-lib:3.0.0:*:*:*:*:*:*:*")
	transitiveDep.CPE = cpe

	finding := &VulnerabilityFinding{
		CVE: &CVEReference{
			CVEID: "CVE-2023-0003",
			AffectedCPEs: []string{
				"cpe:2.3:a:example:transitive-lib:3.0.0:*:*:*:*:*:*:*",
			},
		},
	}

	a := NewDependencyGraphReachabilityAnalyzer()
	a.MaxDepth = 1 // transitive dep is at depth 2
	results, err := a.Analyze(g, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Level != ReachabilityNotReachable {
		t.Errorf("expected level %q, got %q", ReachabilityNotReachable, results[0].Level)
	}
}

// ---------------------------------------------------------------------------
// AnalyzeComponent
// ---------------------------------------------------------------------------

func TestReachability_AnalyzeComponent_NilGraph_ReturnsError(t *testing.T) {
	a := NewDependencyGraphReachabilityAnalyzer()
	comp := &SBOMComponent{Name: "test", Version: "1.0"}
	_, err := a.AnalyzeComponent(nil, comp, []*VulnerabilityFinding{})
	if err == nil {
		t.Fatal("expected error for nil graph, got nil")
	}
}

func TestReachability_AnalyzeComponent_ComponentNotInGraph_ReturnsError(t *testing.T) {
	g, _, _, _ := buildReachabilityTestGraph()
	a := NewDependencyGraphReachabilityAnalyzer()

	unknownComp := &SBOMComponent{Name: "missing", Version: "1.0", BomRef: "missing"}
	_, err := a.AnalyzeComponent(g, unknownComp, []*VulnerabilityFinding{})
	if err == nil {
		t.Fatal("expected error for component not in graph, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestReachability_AnalyzeComponent_DirectComponent(t *testing.T) {
	g, root, _, _ := buildReachabilityTestGraph()

	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0100"}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.AnalyzeComponent(g, root, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Level != ReachabilityDirect {
		t.Errorf("expected level %q, got %q", ReachabilityDirect, results[0].Level)
	}
	if results[0].Confidence < 0.9 {
		t.Errorf("expected confidence >= 0.9 for direct dep, got %f", results[0].Confidence)
	}
}

func TestReachability_AnalyzeComponent_TransitiveComponent(t *testing.T) {
	g, _, _, transitiveDep := buildReachabilityTestGraph()

	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0200"}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.AnalyzeComponent(g, transitiveDep, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Level != ReachabilityTransitive {
		t.Errorf("expected level %q, got %q", ReachabilityTransitive, results[0].Level)
	}
}

// ---------------------------------------------------------------------------
// QuickReachabilityCheck
// ---------------------------------------------------------------------------

func TestReachability_QuickCheck_NilGraph_ReturnsUnknown(t *testing.T) {
	comp := &SBOMComponent{Name: "test", Version: "1.0"}
	finding := NewVulnerabilityFinding()

	result := QuickReachabilityCheck(nil, comp, finding)
	if result.Level != ReachabilityUnknown {
		t.Errorf("expected %q for nil graph, got %q", ReachabilityUnknown, result.Level)
	}
	if result.Confidence != 0.0 {
		t.Errorf("expected 0.0 confidence for nil graph, got %f", result.Confidence)
	}
}

func TestReachability_QuickCheck_ValidGraph(t *testing.T) {
	g, root, _, _ := buildReachabilityTestGraph()
	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0300"}

	result := QuickReachabilityCheck(g, root, finding)
	if result.Level != ReachabilityDirect {
		t.Errorf("expected %q, got %q", ReachabilityDirect, result.Level)
	}
	if result.Vulnerability != finding {
		t.Error("result should reference the original finding")
	}
}

// ---------------------------------------------------------------------------
// BatchReachabilityAnalysis
// ---------------------------------------------------------------------------

func TestReachability_BatchAnalysis_MultipleGraphs(t *testing.T) {
	g1, _, _, _ := buildReachabilityTestGraph()
	g2 := NewDependencyGraph()

	comp := &SBOMComponent{BomRef: "g2-app", Name: "g2-app", Version: "1.0"}
	dep := &SBOMComponent{BomRef: "g2-lib", Name: "g2-lib", Version: "1.0"}
	g2.AddComponent(comp, []*SBOMComponent{dep})

	findings := []*VulnerabilityFinding{
		NewVulnerabilityFinding(),
	}

	results, err := BatchReachabilityAnalysis([]*DependencyGraph{g1, g2}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 graph results, got %d", len(results))
	}
}

func TestReachability_BatchAnalysis_NilGraphInSlice(t *testing.T) {
	findings := []*VulnerabilityFinding{NewVulnerabilityFinding()}

	results, err := BatchReachabilityAnalysis([]*DependencyGraph{nil}, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// nil graph should produce a key but nil results (analyzer.Analyze returns error)
	if len(results) != 1 {
		t.Fatalf("expected 1 entry in results map, got %d", len(results))
	}
}

func TestReachability_BatchAnalysis_EmptySlice(t *testing.T) {
	results, err := BatchReachabilityAnalysis([]*DependencyGraph{}, []*VulnerabilityFinding{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty graphs slice, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// SummarizeReachability (comprehensive tests beyond what new_modules_test.go covers)
// ---------------------------------------------------------------------------

func TestReachability_Summarize_MixedLevels(t *testing.T) {
	results := []*ReachabilityResult{
		{Level: ReachabilityDirect, Confidence: 0.9},
		{Level: ReachabilityDirect, Confidence: 0.9},
		{Level: ReachabilityTransitive, Confidence: 0.8},
		{Level: ReachabilityConditional, Confidence: 0.7},
		{Level: ReachabilityNotReachable, Confidence: 0.6},
		{Level: ReachabilityUnknown, Confidence: 0.5},
	}

	summary := SummarizeReachability(results)
	if summary.Total != 6 {
		t.Errorf("expected Total=6, got %d", summary.Total)
	}
	if summary.Direct != 2 {
		t.Errorf("expected Direct=2, got %d", summary.Direct)
	}
	if summary.Transitive != 1 {
		t.Errorf("expected Transitive=1, got %d", summary.Transitive)
	}
	if summary.Conditional != 1 {
		t.Errorf("expected Conditional=1, got %d", summary.Conditional)
	}
	if summary.NotReachable != 1 {
		t.Errorf("expected NotReachable=1, got %d", summary.NotReachable)
	}
	if summary.Unknown != 1 {
		t.Errorf("expected Unknown=1, got %d", summary.Unknown)
	}
	if summary.HighestRiskLevel != string(ReachabilityDirect) {
		t.Errorf("expected HighestRiskLevel=%q, got %q", ReachabilityDirect, summary.HighestRiskLevel)
	}
}

func TestReachability_Summarize_OnlyTransitive(t *testing.T) {
	results := []*ReachabilityResult{
		{Level: ReachabilityTransitive, Confidence: 0.8},
		{Level: ReachabilityNotReachable, Confidence: 0.6},
	}
	summary := SummarizeReachability(results)
	if summary.Direct != 0 {
		t.Errorf("expected Direct=0, got %d", summary.Direct)
	}
	if summary.HighestRiskLevel != string(ReachabilityTransitive) {
		t.Errorf("expected HighestRiskLevel=%q, got %q", ReachabilityTransitive, summary.HighestRiskLevel)
	}
}

func TestReachability_Summarize_EmptyResults(t *testing.T) {
	summary := SummarizeReachability([]*ReachabilityResult{})
	if summary.Total != 0 {
		t.Errorf("expected Total=0, got %d", summary.Total)
	}
	if summary.HighestRiskLevel != string(ReachabilityUnknown) {
		t.Errorf("expected HighestRiskLevel=%q for empty results, got %q", ReachabilityUnknown, summary.HighestRiskLevel)
	}
}

func TestReachability_Summarize_OnlyNotReachable(t *testing.T) {
	results := []*ReachabilityResult{
		{Level: ReachabilityNotReachable, Confidence: 0.6},
	}
	summary := SummarizeReachability(results)
	if summary.NotReachable != 1 {
		t.Errorf("expected NotReachable=1, got %d", summary.NotReachable)
	}
	// No direct/transitive/conditional, so HighestRiskLevel falls to "unknown"
	if summary.HighestRiskLevel != string(ReachabilityUnknown) {
		t.Errorf("expected HighestRiskLevel=%q, got %q", ReachabilityUnknown, summary.HighestRiskLevel)
	}
}

func TestReachability_Summarize_ConditionalOnly(t *testing.T) {
	results := []*ReachabilityResult{
		{Level: ReachabilityConditional, Confidence: 0.7},
	}
	summary := SummarizeReachability(results)
	if summary.HighestRiskLevel != string(ReachabilityConditional) {
		t.Errorf("expected HighestRiskLevel=%q, got %q", ReachabilityConditional, summary.HighestRiskLevel)
	}
}

// ---------------------------------------------------------------------------
// GetActionableFindings (comprehensive tests beyond what new_modules_test.go covers)
// ---------------------------------------------------------------------------

func TestReachability_ActionableFindings_FiltersNotReachable(t *testing.T) {
	directFinding := &VulnerabilityFinding{Reachability: "direct"}
	transitiveFinding := &VulnerabilityFinding{Reachability: "transitive"}
	notReachableFinding := &VulnerabilityFinding{Reachability: "not_reachable"}
	unknownFinding := &VulnerabilityFinding{Reachability: "unknown"}

	results := []*ReachabilityResult{
		{Vulnerability: directFinding, Level: ReachabilityDirect},
		{Vulnerability: transitiveFinding, Level: ReachabilityTransitive},
		{Vulnerability: notReachableFinding, Level: ReachabilityNotReachable},
		{Vulnerability: unknownFinding, Level: ReachabilityUnknown},
	}

	actionable := GetActionableFindings(results)
	// Only not_reachable is excluded; unknown, direct, transitive are kept
	if len(actionable) != 3 {
		t.Fatalf("expected 3 actionable findings, got %d", len(actionable))
	}

	// Verify not_reachable is excluded
	for _, f := range actionable {
		if f.Reachability == "not_reachable" {
			t.Error("not_reachable finding should not be in actionable results")
		}
	}
}

func TestReachability_ActionableFindings_AllNotReachable(t *testing.T) {
	results := []*ReachabilityResult{
		{Vulnerability: &VulnerabilityFinding{Reachability: "not_reachable"}, Level: ReachabilityNotReachable},
		{Vulnerability: &VulnerabilityFinding{Reachability: "not_reachable"}, Level: ReachabilityNotReachable},
	}
	actionable := GetActionableFindings(results)
	if len(actionable) != 0 {
		t.Errorf("expected 0 actionable findings, got %d", len(actionable))
	}
}

func TestReachability_ActionableFindings_EmptyInput(t *testing.T) {
	actionable := GetActionableFindings([]*ReachabilityResult{})
	if len(actionable) != 0 {
		t.Errorf("expected 0 actionable findings, got %d", len(actionable))
	}
}

func TestReachability_ActionableFindings_ConditionalIncluded(t *testing.T) {
	conditionalFinding := &VulnerabilityFinding{Reachability: "conditional"}
	results := []*ReachabilityResult{
		{Vulnerability: conditionalFinding, Level: ReachabilityConditional},
	}
	actionable := GetActionableFindings(results)
	if len(actionable) != 1 {
		t.Errorf("expected 1 actionable finding (conditional), got %d", len(actionable))
	}
}

// ---------------------------------------------------------------------------
// ReachabilityResult fields
// ---------------------------------------------------------------------------

func TestReachability_Result_DirectHasHighConfidence(t *testing.T) {
	g, root, _, _ := buildReachabilityTestGraph()
	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0400"}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.AnalyzeComponent(g, root, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := results[0]
	if r.Confidence != 0.9 {
		t.Errorf("expected confidence 0.9 for direct, got %f", r.Confidence)
	}
	if r.Evidence == "" {
		t.Error("expected non-empty evidence for direct dependency")
	}
	if !strings.Contains(r.Evidence, "direct dependency") {
		t.Errorf("evidence should mention 'direct dependency', got: %s", r.Evidence)
	}
}

func TestReachability_Result_TransitiveHasPath(t *testing.T) {
	g, _, _, transitiveDep := buildReachabilityTestGraph()
	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0500"}

	a := NewDependencyGraphReachabilityAnalyzer()
	results, err := a.AnalyzeComponent(g, transitiveDep, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r := results[0]
	if r.Level != ReachabilityTransitive {
		t.Errorf("expected level %q, got %q", ReachabilityTransitive, r.Level)
	}
	if r.Confidence != 0.8 {
		t.Errorf("expected confidence 0.8 for transitive, got %f", r.Confidence)
	}
	if !strings.Contains(r.Evidence, "transitive dependency") {
		t.Errorf("evidence should mention 'transitive dependency', got: %s", r.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Analyze updates finding.Reachability
// ---------------------------------------------------------------------------

func TestReachability_Analyze_UpdatesFindingReachability(t *testing.T) {
	g, root, _, _ := buildReachabilityTestGraph()
	finding := NewVulnerabilityFinding()
	finding.CVE = &CVEReference{CVEID: "CVE-2023-0600"}

	a := NewDependencyGraphReachabilityAnalyzer()
	_, err := a.AnalyzeComponent(g, root, []*VulnerabilityFinding{finding})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if finding.Reachability != string(ReachabilityDirect) {
		t.Errorf("expected finding.Reachability=%q, got %q", ReachabilityDirect, finding.Reachability)
	}
}
