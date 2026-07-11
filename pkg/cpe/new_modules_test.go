package cpeskills

import (
	"testing"
)

// ===== Vendor Normalization Tests =====

func TestNewVendorNormalizer(t *testing.T) {
	n := NewVendorNormalizer()
	if n == nil {
		t.Fatal("NewVendorNormalizer returned nil")
	}
	if n.VendorCount() == 0 {
		t.Error("expected non-zero vendor count with built-in aliases")
	}
}

func TestNormalizeVendor(t *testing.T) {
	n := NewVendorNormalizer()

	tests := []struct {
		input    string
		expected string
	}{
		{"apache_software_foundation", "apache"},
		{"Apache Software Foundation", "apache"},
		{"THE APACHE SOFTWARE FOUNDATION", "apache"},
		{"apache", "apache"},
		{"microsoft_corporation", "microsoft"},
		{"Microsoft Corporation", "microsoft"},
		{"red_hat", "redhat"},
		{"Red Hat, Inc.", "redhat"},
		{"google_inc", "google"},
		{"oracle_corporation", "oracle"},
		{"python_software_foundation", "python"},
		{"node.js", "nodejs"},
		{"ibm", "ibm"},
		{"cisco_systems", "cisco"},
		{"apple_inc", "apple"},
		{"mozilla_foundation", "mozilla"},
		{"debian_project", "debian"},
		{"canonical", "ubuntu"},
		{"vmware_inc", "vmware"},
	}

	for _, tt := range tests {
		result := n.NormalizeVendor(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeVendorUnknown(t *testing.T) {
	n := NewVendorNormalizer()
	result := n.NormalizeVendor("unknown_vendor_xyz")
	if result != "unknown_vendor_xyz" {
		t.Errorf("expected unknown vendor to pass through, got %q", result)
	}
}

func TestNormalizeProduct(t *testing.T) {
	n := NewVendorNormalizer()

	tests := []struct {
		vendor   string
		product  string
		expected string
	}{
		{"apache", "log4j2", "log4j"},
		{"apache", "apache_tomcat", "tomcat"},
		{"apache", "apache_http_server", "httpd"},
		{"microsoft", "windows_10", "windows"},
		{"microsoft", "microsoft_office", "office"},
		{"google", "google_chrome", "chrome"},
		{"oracle", "mysql_server", "mysql"},
		{"any", "openssl", "openssl"},
		{"any", "nginx_http_server", "nginx"},
		{"any", "k8s", "kubernetes"},
		{"any", "docker_engine", "docker"},
	}

	for _, tt := range tests {
		result := n.NormalizeProduct(tt.vendor, tt.product)
		if result != tt.expected {
			t.Errorf("NormalizeProduct(%q, %q) = %q, want %q", tt.vendor, tt.product, result, tt.expected)
		}
	}
}

func TestAreSameVendor(t *testing.T) {
	n := NewVendorNormalizer()

	tests := []struct {
		a        string
		b        string
		expected bool
	}{
		{"apache", "apache_software_foundation", true},
		{"microsoft", "Microsoft Corporation", true},
		{"google", "apache", false},
		{"red_hat", "redhat", true},
	}

	for _, tt := range tests {
		result := n.AreSameVendor(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("AreSameVendor(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
		}
	}
}

func TestRegisterVendorAlias(t *testing.T) {
	n := NewVendorNormalizer()
	n.RegisterVendorAlias("myvendor", "my_vendor_inc", "My Vendor Inc")

	if !n.AreSameVendor("myvendor", "my_vendor_inc") {
		t.Error("expected custom alias to work")
	}
	if !n.AreSameVendor("myvendor", "My Vendor Inc") {
		t.Error("expected custom alias with spaces to work")
	}
}

func TestRegisterProductAlias(t *testing.T) {
	n := NewVendorNormalizer()
	n.RegisterProductAlias("myproduct", "my_product_pro", "My Product Pro")

	result := n.NormalizeProduct("any", "my_product_pro")
	if result != "myproduct" {
		t.Errorf("expected 'myproduct', got %q", result)
	}
}

func TestHasVendor(t *testing.T) {
	n := NewVendorNormalizer()
	if !n.HasVendor("apache") {
		t.Error("expected 'apache' to be known")
	}
	if n.HasVendor("nonexistent_vendor_xyz_12345") {
		t.Error("expected unknown vendor to not be found")
	}
}

func TestVendorNormalizerNormalizeCPE(t *testing.T) {
	n := NewVendorNormalizer()
	cpe, err := ParseCpe23("cpe:2.3:a:apache_software_foundation:log4j:2.14.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Skipf("ParseCpe23 failed: %v", err)
	}

	normalized := n.NormalizeCPE(cpe)
	if normalized == nil {
		t.Fatal("NormalizeCPE returned nil")
	}
	if string(normalized.Vendor) != "apache" {
		t.Errorf("expected vendor 'apache', got %q", normalized.Vendor)
	}
}

func TestGlobalVendorNormalizer(t *testing.T) {
	result := NormalizeVendorName("apache_software_foundation")
	if result != "apache" {
		t.Errorf("NormalizeVendorName = %q, want 'apache'", result)
	}
}

// ===== Logger Tests =====

func TestNewDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger(nil, LogLevelInfo)
	if logger == nil {
		t.Fatal("NewDefaultLogger returned nil")
	}
}

func TestNewNopLogger(t *testing.T) {
	logger := NewNopLogger()
	if logger == nil {
		t.Fatal("NewNopLogger returned nil")
	}
	// These should not panic
	logger.Debug("test")
	logger.Info("test")
	logger.Warn("test")
	logger.Error("test")
}

func TestDefaultLoggerLevels(t *testing.T) {
	logger := NewDefaultLogger(nil, LogLevelWarn)

	// These should not produce output (below threshold)
	logger.Debug("debug message")
	logger.Info("info message")

	// These should produce output
	logger.Warn("warn message")
	logger.Error("error message")
}

func TestDefaultLoggerWith(t *testing.T) {
	logger := NewDefaultLogger(nil, LogLevelInfo)
	child := logger.With("component", "test")
	if child == nil {
		t.Fatal("With returned nil")
	}
}

func TestDefaultLoggerSetLevel(t *testing.T) {
	logger := NewDefaultLogger(nil, LogLevelInfo)
	logger.SetLevel(LogLevelDebug)
	// After level change, debug should be enabled
	logger.Debug("should appear now")
}

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LogLevelDebug, "DEBUG"},
		{LogLevelInfo, "INFO"},
		{LogLevelWarn, "WARN"},
		{LogLevelError, "ERROR"},
		{LogLevelOff, "OFF"},
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tt.level, tt.level.String(), tt.expected)
		}
	}
}

func TestSetLogger(t *testing.T) {
	original := GetLogger()
	SetLogger(NewDefaultLogger(nil, LogLevelInfo))
	SetLogger(original) // restore
}

func TestGlobalLogFunctions(t *testing.T) {
	// Should not panic
	LogDebug("test debug", "key", "value")
	LogInfo("test info", "key", "value")
	LogWarn("test warn", "key", "value")
	LogError("test error", "key", "value")
}

// ===== SBOM Enhanced Tests =====

func TestSBOMDiffNoChanges(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom2 := NewSBOM(SBOMFormatCycloneDX, "test")

	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	sbom1.AddComponent(comp1)

	comp2 := NewSBOMComponent("lib-a", "1.0.0")
	comp2.BomRef = "ref-a"
	sbom2.AddComponent(comp2)

	diff := DiffSBOMs(sbom1, sbom2)
	if diff.HasChanges() {
		t.Error("expected no changes for identical SBOMs")
	}
	if diff.Unchanged != 1 {
		t.Errorf("expected 1 unchanged, got %d", diff.Unchanged)
	}
}

func TestSBOMDiffAdded(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom2 := NewSBOM(SBOMFormatCycloneDX, "test")

	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	sbom1.AddComponent(comp1)

	comp2 := NewSBOMComponent("lib-a", "1.0.0")
	comp2.BomRef = "ref-a"
	comp3 := NewSBOMComponent("lib-b", "2.0.0")
	comp3.BomRef = "ref-b"
	sbom2.AddComponent(comp2)
	sbom2.AddComponent(comp3)

	diff := DiffSBOMs(sbom1, sbom2)
	if len(diff.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(diff.Added))
	}
}

func TestSBOMDiffRemoved(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom2 := NewSBOM(SBOMFormatCycloneDX, "test")

	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	comp2 := NewSBOMComponent("lib-b", "2.0.0")
	comp2.BomRef = "ref-b"
	sbom1.AddComponent(comp1)
	sbom1.AddComponent(comp2)

	comp3 := NewSBOMComponent("lib-a", "1.0.0")
	comp3.BomRef = "ref-a"
	sbom2.AddComponent(comp3)

	diff := DiffSBOMs(sbom1, sbom2)
	if len(diff.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(diff.Removed))
	}
}

func TestSBOMDiffChanged(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom2 := NewSBOM(SBOMFormatCycloneDX, "test")

	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	sbom1.AddComponent(comp1)

	comp2 := NewSBOMComponent("lib-a", "2.0.0")
	comp2.BomRef = "ref-a"
	sbom2.AddComponent(comp2)

	diff := DiffSBOMs(sbom1, sbom2)
	if len(diff.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(diff.Changed))
	}
	if diff.Changed[0].OldVersion != "1.0.0" {
		t.Errorf("expected old version '1.0.0', got %q", diff.Changed[0].OldVersion)
	}
	if diff.Changed[0].NewVersion != "2.0.0" {
		t.Errorf("expected new version '2.0.0', got %q", diff.Changed[0].NewVersion)
	}
	if diff.Changed[0].ChangeType != "upgrade" {
		t.Errorf("expected change type 'upgrade', got %q", diff.Changed[0].ChangeType)
	}
}

func TestSBOMDiffNil(t *testing.T) {
	diff := DiffSBOMs(nil, nil)
	if diff.HasChanges() {
		t.Error("expected no changes for nil SBOMs")
	}
}

func TestSBOMDiffSummary(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "test")
	sbom2 := NewSBOM(SBOMFormatCycloneDX, "test")

	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	sbom1.AddComponent(comp1)

	comp2 := NewSBOMComponent("lib-b", "2.0.0")
	comp2.BomRef = "ref-b"
	sbom2.AddComponent(comp2)

	diff := DiffSBOMs(sbom1, sbom2)
	summary := diff.Summary()
	if summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestMergeSBOMs(t *testing.T) {
	sbom1 := NewSBOM(SBOMFormatCycloneDX, "merged")
	comp1 := NewSBOMComponent("lib-a", "1.0.0")
	comp1.BomRef = "ref-a"
	sbom1.AddComponent(comp1)

	sbom2 := NewSBOM(SBOMFormatCycloneDX, "merged")
	comp2 := NewSBOMComponent("lib-b", "2.0.0")
	comp2.BomRef = "ref-b"
	sbom2.AddComponent(comp2)

	merged, err := MergeSBOMs([]*SBOM{sbom1, sbom2}, SBOMFormatCycloneDX, "merged")
	if err != nil {
		t.Fatalf("MergeSBOMs failed: %v", err)
	}
	if len(merged.Components) != 2 {
		t.Errorf("expected 2 components, got %d", len(merged.Components))
	}
}

func TestMergeSBOMsEmpty(t *testing.T) {
	_, err := MergeSBOMs(nil, SBOMFormatCycloneDX, "test")
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestDeduplicateComponents(t *testing.T) {
	components := []*SBOMComponent{
		{Name: "lib-a", Version: "1.0.0", BomRef: "ref-a"},
		{Name: "lib-a", Version: "1.0.0", BomRef: "ref-a"},
		{Name: "lib-b", Version: "2.0.0", BomRef: "ref-b"},
	}

	deduped := DeduplicateComponents(components)
	if len(deduped) != 2 {
		t.Errorf("expected 2 deduplicated components, got %d", len(deduped))
	}
}

func TestValidateSBOM(t *testing.T) {
	sbom := NewSBOM(SBOMFormatCycloneDX, "test")
	issues := ValidateSBOM(sbom)
	if len(issues) != 0 {
		t.Errorf("expected no issues for valid SBOM, got %d: %v", len(issues), issues)
	}
}

func TestValidateSBOMNil(t *testing.T) {
	issues := ValidateSBOM(nil)
	if len(issues) == 0 {
		t.Error("expected issues for nil SBOM")
	}
}

func TestNewSBOMPedigree(t *testing.T) {
	p := NewSBOMPedigree()
	if p == nil {
		t.Fatal("NewSBOMPedigree returned nil")
	}
	if len(p.Ancestors) != 0 {
		t.Errorf("expected 0 ancestors, got %d", len(p.Ancestors))
	}
}

func TestSBOMPedigreeAddAncestor(t *testing.T) {
	p := NewSBOMPedigree()
	comp := NewSBOMComponent("parent", "1.0.0")
	p.AddAncestor(comp)
	if len(p.Ancestors) != 1 {
		t.Errorf("expected 1 ancestor, got %d", len(p.Ancestors))
	}
}

func TestSBOMPedigreeAddCommit(t *testing.T) {
	p := NewSBOMPedigree()
	p.AddCommit("abc123", "https://github.com/repo", "fix: security issue")
	if len(p.Commits) != 1 {
		t.Errorf("expected 1 commit, got %d", len(p.Commits))
	}
	if p.Commits[0].UID != "abc123" {
		t.Errorf("expected UID 'abc123', got %q", p.Commits[0].UID)
	}
}

func TestNewSBOMEvidence(t *testing.T) {
	e := NewSBOMEvidence("filename", "lib/test.jar", 0.95)
	if e.Field != "filename" {
		t.Errorf("expected Field 'filename', got %q", e.Field)
	}
	if e.Confidence != 0.95 {
		t.Errorf("expected Confidence 0.95, got %f", e.Confidence)
	}
}

func TestSetComponentCopyright(t *testing.T) {
	comp := NewSBOMComponent("lib-a", "1.0.0")
	SetComponentCopyright(comp, "Copyright 2024 Example Corp")
	if comp.Properties["cpe:copyright"] != "Copyright 2024 Example Corp" {
		t.Errorf("expected copyright in properties, got %q", comp.Properties["cpe:copyright"])
	}
}

func TestSortComponentsByName(t *testing.T) {
	components := []*SBOMComponent{
		{Name: "zlib"},
		{Name: "abc"},
		{Name: "middle"},
	}
	SortComponentsByName(components)
	if components[0].Name != "abc" {
		t.Errorf("expected first component 'abc', got %q", components[0].Name)
	}
	if components[2].Name != "zlib" {
		t.Errorf("expected last component 'zlib', got %q", components[2].Name)
	}
}

// ===== Reachability Tests =====

func TestReachabilityLevelConstants(t *testing.T) {
	if ReachabilityDirect != "direct" {
		t.Errorf("ReachabilityDirect = %q", ReachabilityDirect)
	}
	if ReachabilityTransitive != "transitive" {
		t.Errorf("ReachabilityTransitive = %q", ReachabilityTransitive)
	}
	if ReachabilityNotReachable != "not_reachable" {
		t.Errorf("ReachabilityNotReachable = %q", ReachabilityNotReachable)
	}
}

func TestNewDependencyGraphReachabilityAnalyzerBasic(t *testing.T) {
	analyzer := NewDependencyGraphReachabilityAnalyzer()
	if analyzer == nil {
		t.Fatal("NewDependencyGraphReachabilityAnalyzer returned nil")
	}
}

func TestReachabilityAnalyzerNilGraph(t *testing.T) {
	analyzer := NewDependencyGraphReachabilityAnalyzer()
	_, err := analyzer.Analyze(nil, nil)
	if err == nil {
		t.Error("expected error for nil graph")
	}
}

func TestSummarizeReachability(t *testing.T) {
	results := []*ReachabilityResult{
		{Level: ReachabilityDirect},
		{Level: ReachabilityDirect},
		{Level: ReachabilityTransitive},
		{Level: ReachabilityNotReachable},
		{Level: ReachabilityUnknown},
	}

	summary := SummarizeReachability(results)
	if summary.Total != 5 {
		t.Errorf("expected Total 5, got %d", summary.Total)
	}
	if summary.Direct != 2 {
		t.Errorf("expected Direct 2, got %d", summary.Direct)
	}
	if summary.Transitive != 1 {
		t.Errorf("expected Transitive 1, got %d", summary.Transitive)
	}
	if summary.NotReachable != 1 {
		t.Errorf("expected NotReachable 1, got %d", summary.NotReachable)
	}
	if summary.Unknown != 1 {
		t.Errorf("expected Unknown 1, got %d", summary.Unknown)
	}
	if summary.HighestRiskLevel != string(ReachabilityDirect) {
		t.Errorf("expected HighestRiskLevel 'direct', got %q", summary.HighestRiskLevel)
	}
}

func TestGetActionableFindings(t *testing.T) {
	findings := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-1"}, Reachability: "direct"},
		{CVE: &CVEReference{CVEID: "CVE-2"}, Reachability: "not_reachable"},
		{CVE: &CVEReference{CVEID: "CVE-3"}, Reachability: "transitive"},
	}

	results := []*ReachabilityResult{
		{Vulnerability: findings[0], Level: ReachabilityDirect},
		{Vulnerability: findings[1], Level: ReachabilityNotReachable},
		{Vulnerability: findings[2], Level: ReachabilityTransitive},
	}

	actionable := GetActionableFindings(results)
	if len(actionable) != 2 {
		t.Errorf("expected 2 actionable findings, got %d", len(actionable))
	}
}
