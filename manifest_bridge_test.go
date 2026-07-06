package cpeskills

import (
	"strings"
	"testing"

	"github.com/scagogogo/cpe-skills/pkg/parsers"
)

// --- ParseManifestFile ---

func TestParseManifestFile_GoMod(t *testing.T) {
	content := `module github.com/example/project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	github.com/stretchr/testify v1.8.0 // indirect
)
`
	components, err := ParseManifestFile("go.mod", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	// First component: direct dependency
	comp := components[0]
	if comp.Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected name 'github.com/gin-gonic/gin', got %q", comp.Name)
	}
	if comp.Version != "v1.9.0" {
		t.Errorf("expected version 'v1.9.0', got %q", comp.Version)
	}
	if comp.Type != "library" {
		t.Errorf("expected type 'library', got %q", comp.Type)
	}
	if comp.PURL == nil {
		t.Error("expected non-nil PURL")
	}
	if comp.Properties["cpe:dependencyType"] != "direct" {
		t.Errorf("expected dependencyType 'direct', got %q", comp.Properties["cpe:dependencyType"])
	}
	if comp.Properties["cpe:ecosystem"] != "golang" {
		t.Errorf("expected ecosystem 'golang', got %q", comp.Properties["cpe:ecosystem"])
	}

	// Second component: indirect dependency
	comp2 := components[1]
	if comp2.Name != "github.com/stretchr/testify" {
		t.Errorf("expected name 'github.com/stretchr/testify', got %q", comp2.Name)
	}
	if comp2.Properties["cpe:dependencyType"] != "transitive" {
		t.Errorf("expected dependencyType 'transitive', got %q", comp2.Properties["cpe:dependencyType"])
	}
}

func TestParseManifestFile_PackageJSON(t *testing.T) {
	content := `{
		"name": "my-app",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.2"
		},
		"devDependencies": {
			"jest": "^29.5.0"
		}
	}`
	components, err := ParseManifestFile("package.json", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}

	// Production dependency
	comp := components[0]
	if comp.Name != "express" {
		t.Errorf("expected name 'express', got %q", comp.Name)
	}
	if comp.Properties["cpe:ecosystem"] != "npm" {
		t.Errorf("expected ecosystem 'npm', got %q", comp.Properties["cpe:ecosystem"])
	}
	if comp.Properties["cpe:dependencyType"] != "direct" {
		t.Errorf("expected dependencyType 'direct', got %q", comp.Properties["cpe:dependencyType"])
	}
	if _, ok := comp.Properties["cpe:devDependency"]; ok {
		t.Error("expected no devDependency property for production dependency")
	}

	// Dev dependency
	comp2 := components[1]
	if comp2.Name != "jest" {
		t.Errorf("expected name 'jest', got %q", comp2.Name)
	}
	if comp2.Properties["cpe:devDependency"] != "true" {
		t.Errorf("expected devDependency 'true', got %q", comp2.Properties["cpe:devDependency"])
	}
}

func TestParseManifestFile_UnsupportedFileType(t *testing.T) {
	_, err := ParseManifestFile("unknown.xyz", "some content")
	if err == nil {
		t.Fatal("expected error for unsupported file type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported manifest file") {
		t.Errorf("expected error to mention unsupported manifest file, got %q", err.Error())
	}
}

func TestParseManifestFile_InvalidContent(t *testing.T) {
	// package.json expects valid JSON; invalid JSON should produce an error
	_, err := ParseManifestFile("package.json", "{not valid json!!!")
	if err == nil {
		t.Fatal("expected error for invalid content, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse package.json") {
		t.Errorf("expected error wrapping parse failure, got %q", err.Error())
	}
}

// --- ConvertMappingsToComponents ---

func TestConvertMappingsToComponents_ValidMappings(t *testing.T) {
	mappings := []parsers.ComponentMapping{
		{
			Name:      "express",
			Version:   "4.18.2",
			Namespace: "",
			PURLType:  "npm",
			Ecosystem: "npm",
			IsDirect:  true,
			IsDev:     false,
		},
		{
			Name:      "log4j-core",
			Version:   "2.14.1",
			Namespace: "org.apache.logging.log4j",
			PURLType:  "maven",
			Ecosystem: "maven",
			IsDirect:  true,
			IsDev:     false,
		},
		{
			Name:      "jest",
			Version:   "29.5.0",
			Namespace: "",
			PURLType:  "npm",
			Ecosystem: "npm",
			IsDirect:  true,
			IsDev:     true,
		},
	}

	components := ConvertMappingsToComponents(mappings)
	if len(components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(components))
	}

	// First: express (no namespace)
	comp := components[0]
	if comp.Name != "express" {
		t.Errorf("expected name 'express', got %q", comp.Name)
	}
	if comp.Version != "4.18.2" {
		t.Errorf("expected version '4.18.2', got %q", comp.Version)
	}
	if comp.Type != "library" {
		t.Errorf("expected type 'library', got %q", comp.Type)
	}
	if comp.PURL == nil || !comp.PURL.IsValid() {
		t.Error("expected valid PURL for express")
	}
	if comp.Properties["cpe:ecosystem"] != "npm" {
		t.Errorf("expected ecosystem 'npm', got %q", comp.Properties["cpe:ecosystem"])
	}
	if comp.Properties["cpe:dependencyType"] != "direct" {
		t.Errorf("expected dependencyType 'direct', got %q", comp.Properties["cpe:dependencyType"])
	}
	if comp.Group != "" {
		t.Errorf("expected empty group for component without namespace, got %q", comp.Group)
	}

	// Second: log4j-core (with namespace → Group)
	comp2 := components[1]
	if comp2.Name != "log4j-core" {
		t.Errorf("expected name 'log4j-core', got %q", comp2.Name)
	}
	if comp2.Group != "org.apache.logging.log4j" {
		t.Errorf("expected group 'org.apache.logging.log4j', got %q", comp2.Group)
	}
	if comp2.PURL == nil || comp2.PURL.Namespace != "org.apache.logging.log4j" {
		t.Error("expected PURL with namespace for log4j-core")
	}

	// Third: jest (dev dependency)
	comp3 := components[2]
	if comp3.Properties["cpe:devDependency"] != "true" {
		t.Errorf("expected devDependency 'true', got %q", comp3.Properties["cpe:devDependency"])
	}
}

func TestConvertMappingsToComponents_EmptyMappings(t *testing.T) {
	components := ConvertMappingsToComponents([]parsers.ComponentMapping{})
	if len(components) != 0 {
		t.Errorf("expected 0 components for empty mappings, got %d", len(components))
	}

	// nil slice should also work
	componentsNil := ConvertMappingsToComponents(nil)
	if len(componentsNil) != 0 {
		t.Errorf("expected 0 components for nil mappings, got %d", len(componentsNil))
	}
}

// --- BuildSBOMFromManifest ---

func TestBuildSBOMFromManifest_ValidGoMod(t *testing.T) {
	content := `module github.com/example/app

go 1.21

require github.com/gin-gonic/gin v1.9.0
`
	sbom, err := BuildSBOMFromManifest("go.mod", content, "my-app-sbom")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
	if sbom.Name != "my-app-sbom" {
		t.Errorf("expected SBOM name 'my-app-sbom', got %q", sbom.Name)
	}
	if sbom.Format != SBOMFormatCycloneDX {
		t.Errorf("expected format CycloneDX, got %q", sbom.Format)
	}
	if sbom.ComponentCount() != 1 {
		t.Fatalf("expected 1 component, got %d", sbom.ComponentCount())
	}

	// Verify the tool was added
	if len(sbom.Metadata.Tools) != 1 {
		t.Fatalf("expected 1 tool in metadata, got %d", len(sbom.Metadata.Tools))
	}
	if sbom.Metadata.Tools[0].Name != "cpe-skills" {
		t.Errorf("expected tool name 'cpe-skills', got %q", sbom.Metadata.Tools[0].Name)
	}
	if sbom.Metadata.Tools[0].Version != "1.0.0" {
		t.Errorf("expected tool version '1.0.0', got %q", sbom.Metadata.Tools[0].Version)
	}

	// Verify component was properly added
	comp := sbom.Components[0]
	if comp.Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected component name 'github.com/gin-gonic/gin', got %q", comp.Name)
	}
	if comp.Version != "v1.9.0" {
		t.Errorf("expected component version 'v1.9.0', got %q", comp.Version)
	}
}

func TestBuildSBOMFromManifest_InvalidFileType(t *testing.T) {
	_, err := BuildSBOMFromManifest("unknown.xyz", "some content", "test-sbom")
	if err == nil {
		t.Fatal("expected error for unsupported file type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported manifest file") {
		t.Errorf("expected error about unsupported manifest, got %q", err.Error())
	}
}

func TestParseManifestToComponents_GoMod(t *testing.T) {
	content := `module github.com/example/project

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
)
`
	result, err := ParseManifestToComponents("go.mod", content)
	if err != nil {
		t.Fatalf("ParseManifestToComponents: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Components) == 0 {
		t.Error("expected components in parse result")
	}
}

func TestParseManifestToComponents_Unsupported(t *testing.T) {
	_, err := ParseManifestToComponents("unknown.xyz", "content")
	if err == nil {
		t.Error("expected error for unsupported file type")
	}
}
