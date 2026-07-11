package cpeskills

import (
	"testing"
)

func TestCPEBuilderBasic(t *testing.T) {
	cpe, err := NewCPEBuilder().
		Application().
		Vendor("microsoft").
		Product("windows").
		Version("10").
		Build()

	if err != nil {
		t.Fatalf("CPEBuilder.Build() error = %v", err)
	}

	if cpe.Part.ShortName != "a" {
		t.Errorf("Part = %q, want %q", cpe.Part.ShortName, "a")
	}
	if cpe.Vendor != "microsoft" {
		t.Errorf("Vendor = %q, want %q", cpe.Vendor, "microsoft")
	}
	if cpe.ProductName != "windows" {
		t.Errorf("ProductName = %q, want %q", cpe.ProductName, "windows")
	}
	if cpe.Version != "10" {
		t.Errorf("Version = %q, want %q", cpe.Version, "10")
	}
}

func TestCPEBuilderAllFields(t *testing.T) {
	cpe, err := NewCPEBuilder().
		OS().
		Vendor("linux").
		Product("linux_kernel").
		Version("5.10").
		Update("sp1").
		Edition("pro").
		Language("en").
		SoftwareEdition("enterprise").
		TargetSoftware("ubuntu").
		TargetHardware("x86").
		Other("custom").
		Build()

	if err != nil {
		t.Fatalf("CPEBuilder.Build() error = %v", err)
	}

	if cpe.Part.ShortName != "o" {
		t.Errorf("Part = %q, want %q", cpe.Part.ShortName, "o")
	}
	if cpe.Update != "sp1" {
		t.Errorf("Update = %q, want %q", cpe.Update, "sp1")
	}
	if cpe.SoftwareEdition != "enterprise" {
		t.Errorf("SoftwareEdition = %q, want %q", cpe.SoftwareEdition, "enterprise")
	}
}

func TestCPEBuilderInvalidPart(t *testing.T) {
	_, err := NewCPEBuilder().
		Part("x").
		Vendor("microsoft").
		Product("windows").
		Version("10").
		Build()

	if err == nil {
		t.Error("Expected error for invalid part, got nil")
	}
}

func TestCPEBuilderHardware(t *testing.T) {
	cpe, err := NewCPEBuilder().
		Hardware().
		Vendor("intel").
		Product("core_i7").
		Version("1068g7").
		Build()

	if err != nil {
		t.Fatalf("CPEBuilder.Build() error = %v", err)
	}

	if cpe.Part.ShortName != "h" {
		t.Errorf("Part = %q, want %q", cpe.Part.ShortName, "h")
	}
}

func TestCPEBuilderMustBuild(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for invalid part, but did not panic")
		}
	}()

	NewCPEBuilder().
		Part("x").
		Vendor("microsoft").
		MustBuild()
}

func TestCPEBuilderBuildWFN(t *testing.T) {
	wfn, err := NewCPEBuilder().
		Application().
		Vendor("microsoft").
		Product("windows").
		Version("10").
		BuildWFN()

	if err != nil {
		t.Fatalf("CPEBuilder.BuildWFN() error = %v", err)
	}

	if wfn.Part != "a" {
		t.Errorf("Part = %q, want %q", wfn.Part, "a")
	}
	if wfn.Vendor != "microsoft" {
		t.Errorf("Vendor = %q, want %q", wfn.Vendor, "microsoft")
	}
}

func TestCPEBuilderErrorPropagation(t *testing.T) {
	builder := NewCPEBuilder().Part("x")
	// Subsequent calls should not modify state after error
	builder.Vendor("microsoft").Product("windows")

	_, err := builder.Build()
	if err == nil {
		t.Error("Expected error after invalid part")
	}
}

func TestCPEBuilderErrorPropagationAllMethods(t *testing.T) {
	// Start with an error, then try all setter methods - they should all skip
	builder := NewCPEBuilder().Part("x")

	// All these should return the builder without modifying the WFN due to existing error
	result := builder.Update("sp1")
	if result != builder {
		t.Error("Update() should return same builder when error exists")
	}

	result = builder.Edition("pro")
	if result != builder {
		t.Error("Edition() should return same builder when error exists")
	}

	result = builder.Language("en")
	if result != builder {
		t.Error("Language() should return same builder when error exists")
	}

	result = builder.SoftwareEdition("enterprise")
	if result != builder {
		t.Error("SoftwareEdition() should return same builder when error exists")
	}

	result = builder.TargetSoftware("linux")
	if result != builder {
		t.Error("TargetSoftware() should return same builder when error exists")
	}

	result = builder.TargetHardware("x86")
	if result != builder {
		t.Error("TargetHardware() should return same builder when error exists")
	}

	result = builder.Other("custom")
	if result != builder {
		t.Error("Other() should return same builder when error exists")
	}

	// BuildWFN should also return error
	_, err := builder.BuildWFN()
	if err == nil {
		t.Error("Expected BuildWFN() to return error")
	}
}

func TestCPEBuilderMustBuildSuccess(t *testing.T) {
	cpe := NewCPEBuilder().
		Application().
		Vendor("microsoft").
		Product("windows").
		Version("10").
		MustBuild()

	if cpe == nil {
		t.Error("MustBuild() should return CPE on success")
	}
	if cpe.Vendor != "microsoft" {
		t.Errorf("Vendor = %q, want %q", cpe.Vendor, "microsoft")
	}
}

func TestCPEBuilderFluentReturns(t *testing.T) {
	builder := NewCPEBuilder()

	// Verify that fluent methods return the same builder instance
	b := builder.Part("a")
	if b != builder {
		t.Error("Part() should return same builder")
	}
	b = builder.Vendor("microsoft")
	if b != builder {
		t.Error("Vendor() should return same builder")
	}
	b = builder.Product("windows")
	if b != builder {
		t.Error("Product() should return same builder")
	}
	b = builder.Version("10")
	if b != builder {
		t.Error("Version() should return same builder")
	}
}

func TestCPEBuilderPartWithExistingError(t *testing.T) {
	// Create builder with an error, then call Part - should skip
	builder := NewCPEBuilder().Part("x") // creates error
	result := builder.Part("a")          // should return early due to error
	if result != builder {
		t.Error("Part() with existing error should return same builder")
	}
	_, err := builder.Build()
	if err == nil {
		t.Error("Expected error from invalid part")
	}
}
