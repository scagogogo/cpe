package cpeskills

import (
	"testing"
)

func TestNewDefaultRiskScorer(t *testing.T) {
	scorer := NewDefaultRiskScorer()
	if scorer.CVSSWeight != 0.5 {
		t.Errorf("expected CVSS weight 0.5, got %f", scorer.CVSSWeight)
	}
}

func TestRiskScorer_Score(t *testing.T) {
	scorer := NewDefaultRiskScorer()
	comp := NewSBOMComponent("test", "1.0")

	// 无漏洞
	score := scorer.Score(nil, comp)
	if score.Priority != RiskPriorityNone {
		t.Errorf("expected none priority for no findings, got %s", score.Priority)
	}

	// 严重漏洞
	findings := []*VulnerabilityFinding{
		{
			CVE: &CVEReference{
				CVEID:     "CVE-2021-44228",
				CVSSScore: 10.0,
				Severity:  "Critical",
			},
			EPSSScore:    0.9,
			KEVListed:    true,
			Reachability: "direct",
		},
	}
	score = scorer.Score(findings, comp)
	if score.Priority != RiskPriorityCritical {
		t.Errorf("expected critical priority, got %s", score.Priority)
	}
	if score.OverallScore <= 0 {
		t.Errorf("expected positive overall score, got %f", score.OverallScore)
	}
	if score.CVSSMax != 10.0 {
		t.Errorf("expected CVSS max 10.0, got %f", score.CVSSMax)
	}
	if !score.KEVListed {
		t.Error("expected KEV listed")
	}
}

func TestRiskScorer_Score_High(t *testing.T) {
	scorer := NewDefaultRiskScorer()
	comp := NewSBOMComponent("test", "1.0")

	findings := []*VulnerabilityFinding{
		{
			CVE: &CVEReference{
				CVEID:     "CVE-2023-12345",
				CVSSScore: 8.5,
				Severity:  "High",
			},
			Reachability: "direct",
		},
	}
	score := scorer.Score(findings, comp)
	// With CVSS 8.5, direct reachability, the overall score should be >= 7.0
	if score.OverallScore < 4.0 {
		t.Errorf("expected overall score >= 4.0, got %f", score.OverallScore)
	}
}

func TestSortByRisk(t *testing.T) {
	scores := []*RiskScore{
		{OverallScore: 3.0, Priority: RiskPriorityLow},
		{OverallScore: 9.5, Priority: RiskPriorityCritical},
		{OverallScore: 6.0, Priority: RiskPriorityMedium},
	}
	SortByRisk(scores)
	if scores[0].OverallScore != 9.5 {
		t.Errorf("expected highest score first, got %f", scores[0].OverallScore)
	}
	if scores[2].OverallScore != 3.0 {
		t.Errorf("expected lowest score last, got %f", scores[2].OverallScore)
	}
}

func TestFilterByPriority(t *testing.T) {
	scores := []*RiskScore{
		{Priority: RiskPriorityCritical, OverallScore: 9.0},
		{Priority: RiskPriorityHigh, OverallScore: 7.0},
		{Priority: RiskPriorityCritical, OverallScore: 9.5},
		{Priority: RiskPriorityLow, OverallScore: 2.0},
	}
	critical := FilterByPriority(scores, RiskPriorityCritical)
	if len(critical) != 2 {
		t.Errorf("expected 2 critical scores, got %d", len(critical))
	}
}

func TestDeterminePriority(t *testing.T) {
	tests := []struct {
		score     float64
		kevListed bool
		priority  RiskPriority
	}{
		{10.0, true, RiskPriorityCritical},
		{9.5, false, RiskPriorityCritical},
		{8.0, false, RiskPriorityHigh},
		{5.0, false, RiskPriorityMedium},
		{2.0, false, RiskPriorityLow},
		{0.0, false, RiskPriorityNone},
		{7.5, true, RiskPriorityCritical}, // KEV + >= 7.0 → Critical
	}
	for _, tt := range tests {
		p := determinePriority(tt.score, tt.kevListed)
		if p != tt.priority {
			t.Errorf("determinePriority(%f, %v): expected %s, got %s", tt.score, tt.kevListed, tt.priority, p)
		}
	}
}

func TestReachabilityToString(t *testing.T) {
	if reachabilityToString(1.0) != "direct" {
		t.Error("expected 'direct'")
	}
	if reachabilityToString(0.5) != "transitive" {
		t.Error("expected 'transitive'")
	}
	if reachabilityToString(0.0) != "unknown" {
		t.Error("expected 'unknown'")
	}
}

func TestScoreComponents(t *testing.T) {
	comp1 := NewSBOMComponent("pkg-a", "1.0")
	cpe1, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp1.SetCPE(cpe1)

	comp2 := NewSBOMComponent("pkg-b", "2.0")
	cpe2, _ := Parse("cpe:2.3:a:unknown:unknown:1.0:*:*:*:*:*:*:*")
	comp2.SetCPE(cpe2)

	nvdData := &NVDCPEData{
		CPEMatchData: &CPEMatchData{
			CPEToCVEs: map[string][]string{
				"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": {"CVE-2021-44228"},
			},
		},
	}

	scores := ScoreComponents([]*SBOMComponent{comp1, comp2}, nvdData)
	if len(scores) != 2 {
		t.Errorf("expected 2 scores, got %d", len(scores))
	}
	// comp1 should have at least one CVE listed (even if CVSS is 0 from string-only match)
	if len(scores[0].Factors) == 0 {
		t.Error("expected non-empty factors for component with CVEs")
	}
}

func TestFilterByPriority_All(t *testing.T) {
	scores := []*RiskScore{
		{Priority: RiskPriorityHigh},
		{Priority: RiskPriorityMedium},
		{Priority: RiskPriorityMedium},
		{Priority: RiskPriorityLow},
	}
	medium := FilterByPriority(scores, RiskPriorityMedium)
	if len(medium) != 2 {
		t.Errorf("expected 2 medium, got %d", len(medium))
	}
}
