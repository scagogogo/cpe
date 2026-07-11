package cpeskills

import (
	"fmt"
	"strings"

	"github.com/scagogogo/cpe-skills/pkg/parsers"
)

// ParseManifestFile parses a manifest/lockfile and returns SBOM components.
//
// This serves as the bridge between the parsers subpackage and the main
// cpe package, converting raw parser results into the SBOM component model.
//
// Supported files are automatically detected by filename:
//   - go.mod, package.json, package-lock.json, requirements.txt
//   - pom.xml, Cargo.toml, composer.json, composer.lock, Gemfile
//
// Example:
//
//	sbom := cpe.NewSBOM(cpe.SBOMFormatCycloneDX, "my-project")
//	components, err := cpe.ParseManifestFile("go.mod", goModContent)
//	for _, comp := range components {
//	    sbom.AddComponent(comp)
//	}
func ParseManifestFile(filename string, content string) ([]*SBOMComponent, error) {
	reader := strings.NewReader(content)
	result, err := parsers.ParseAuto(filename, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", filename, err)
	}

	mappings := parsers.ConvertToSBOMComponents(result)
	return ConvertMappingsToComponents(mappings), nil
}

// ConvertMappingsToComponents converts parser ComponentMapping list to SBOMComponent list.
func ConvertMappingsToComponents(mappings []parsers.ComponentMapping) []*SBOMComponent {
	components := make([]*SBOMComponent, 0, len(mappings))
	for _, m := range mappings {
		component := NewSBOMComponent(m.Name, m.Version)
		component.Type = "library"

		// Set PURL
		purl := NewPURL(m.PURLType, m.Namespace, m.Name, m.Version)
		if purl.IsValid() {
			component.SetPURL(purl)
		}

		// Set group/namespace
		if m.Namespace != "" {
			component.Group = m.Namespace
		}

		// Set properties
		component.SetProperty("cpe:ecosystem", m.Ecosystem)
		if m.IsDirect {
			component.SetProperty("cpe:dependencyType", "direct")
		} else {
			component.SetProperty("cpe:dependencyType", "transitive")
		}
		if m.IsDev {
			component.SetProperty("cpe:devDependency", "true")
		}

		components = append(components, component)
	}
	return components
}

// BuildSBOMFromManifest builds a complete SBOM from a manifest file.
//
// This is a convenience function that creates an SBOM with the appropriate
// format and populates it with components parsed from the manifest.
func BuildSBOMFromManifest(filename string, content string, sbomName string) (*SBOM, error) {
	components, err := ParseManifestFile(filename, content)
	if err != nil {
		return nil, err
	}

	sbom := NewSBOM(SBOMFormatCycloneDX, sbomName)

	// Set metadata
	sbom.Metadata.Tools = append(sbom.Metadata.Tools, &SBOMTool{
		Name:    "cpe-skills",
		Version: "1.0.0",
	})

	for _, comp := range components {
		sbom.AddComponent(comp)
	}

	return sbom, nil
}

// ParseManifestToComponents is a convenience method that parses a manifest
// and returns ComponentInfo directly for advanced use cases.
func ParseManifestToComponents(filename string, content string) (*parsers.ParseResult, error) {
	reader := strings.NewReader(content)
	return parsers.ParseAuto(filename, reader)
}
