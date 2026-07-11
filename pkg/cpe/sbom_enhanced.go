package cpeskills

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// SBOMEvidence captures forensic information about how a component was detected.
type SBOMEvidence struct {
	// Field describes the evidence field (e.g., "filename", "hash", "snippet")
	Field string `json:"field"`

	// Value is the evidence value
	Value string `json:"value"`

	// Confidence is the detection confidence (0.0-1.0)
	Confidence float64 `json:"confidence,omitempty"`
}

// SBOMPedigree captures the lineage/provenance of a component.
type SBOMPedigree struct {
	// Ancestors lists ancestor components
	Ancestors []*SBOMComponent `json:"ancestors,omitempty"`

	// Descendants lists descendant components
	Descendants []*SBOMComponent `json:"descendants,omitempty"`

	// Variants lists variant components
	Variants []*SBOMComponent `json:"variants,omitempty"`

	// Commits lists VCS commits related to this component
	Commits []*SBOMCommit `json:"commits,omitempty"`

	// Patches lists patches applied to this component
	Patches []*SBOMPatch `json:"patches,omitempty"`

	// Notes additional notes
	Notes string `json:"notes,omitempty"`
}

// SBOMCommit represents a VCS commit in the component's pedigree.
type SBOMCommit struct {
	// UID commit hash
	UID string `json:"uid"`

	// URL repository URL
	URL string `json:"url,omitempty"`

	// Author commit author
	Author *SBOMAuthor `json:"author,omitempty"`

	// Message commit message
	Message string `json:"message,omitempty"`
}

// SBOMPatch represents a patch applied to a component.
type SBOMPatch struct {
	// Type patch type (backport, cherry-pick, monkey, etc.)
	Type string `json:"type"`

	// Diff patch diff content or URL
	Diff string `json:"diff,omitempty"`

	// Resolves list of issue IDs resolved by this patch
	Resolves []string `json:"resolves,omitempty"`
}

// SBOMDiff represents the difference between two SBOMs.
type SBOMDiff struct {
	// Added components that exist in the new SBOM but not the old
	Added []*SBOMComponent `json:"added"`

	// Removed components that exist in the old SBOM but not the new
	Removed []*SBOMComponent `json:"removed"`

	// Changed components that exist in both but have different versions
	Changed []*SBOMComponentChange `json:"changed"`

	// Unchanged component count
	Unchanged int `json:"unchanged"`
}

// SBOMComponentChange represents a version change for a component.
type SBOMComponentChange struct {
	// Component the component that changed
	Component *SBOMComponent `json:"component"`

	// OldVersion previous version
	OldVersion string `json:"oldVersion"`

	// NewVersion new version
	NewVersion string `json:"newVersion"`

	// ChangeType upgrade, downgrade, or sidegrade
	ChangeType string `json:"changeType"`
}

// MergeSBOMs merges multiple SBOMs into a single SBOM.
//
// Components are deduplicated by PURL (preferred) or CPE. When duplicates are found,
// the component with the highest version is kept. Dependencies from all SBOMs are preserved.
func MergeSBOMs(sboms []*SBOM, format SBOMFormat, name string) (*SBOM, error) {
	if len(sboms) == 0 {
		return nil, fmt.Errorf("no SBOMs to merge")
	}

	merged := NewSBOM(format, name)

	// Track seen components by PURL or CPE
	seen := make(map[string]*SBOMComponent)

	for _, sbom := range sboms {
		if sbom == nil {
			continue
		}

		for _, comp := range sbom.Components {
			key := componentKey(comp)
			if existing, ok := seen[key]; ok {
				// Keep the higher version
				if comp.Version != "" && existing.Version != "" {
					if CompareVersions(comp.Version, existing.Version) > 0 {
						seen[key] = comp
					}
				}
			} else {
				seen[key] = comp
			}
		}

		// Merge dependencies
		for _, dep := range sbom.Dependencies {
			merged.AddDependency(dep.Ref, dep.DependsOn)
		}

		// Merge metadata tools
		if sbom.Metadata != nil {
			for _, tool := range sbom.Metadata.Tools {
				merged.Metadata.Tools = append(merged.Metadata.Tools, tool)
			}
			for _, author := range sbom.Metadata.Authors {
				merged.Metadata.Authors = append(merged.Metadata.Authors, author)
			}
		}
	}

	// Add deduplicated components
	for _, comp := range seen {
		merged.AddComponent(comp)
	}

	return merged, nil
}

// DiffSBOMs computes the difference between two SBOMs.
//
// Returns a SBOMDiff describing added, removed, and changed components.
func DiffSBOMs(oldSBOM, newSBOM *SBOM) *SBOMDiff {
	diff := &SBOMDiff{}

	if oldSBOM == nil && newSBOM == nil {
		return diff
	}
	if oldSBOM == nil {
		diff.Added = newSBOM.Components
		return diff
	}
	if newSBOM == nil {
		diff.Removed = oldSBOM.Components
		return diff
	}

	// Build lookup maps
	oldMap := make(map[string]*SBOMComponent)
	for _, c := range oldSBOM.Components {
		oldMap[componentKey(c)] = c
	}

	newMap := make(map[string]*SBOMComponent)
	for _, c := range newSBOM.Components {
		newMap[componentKey(c)] = c
	}

	// Find added and changed
	for key, newComp := range newMap {
		oldComp, exists := oldMap[key]
		if !exists {
			diff.Added = append(diff.Added, newComp)
		} else if oldComp.Version != newComp.Version {
			changeType := "upgrade"
			if CompareVersions(newComp.Version, oldComp.Version) < 0 {
				changeType = "downgrade"
			}
			diff.Changed = append(diff.Changed, &SBOMComponentChange{
				Component:  newComp,
				OldVersion: oldComp.Version,
				NewVersion: newComp.Version,
				ChangeType: changeType,
			})
		} else {
			diff.Unchanged++
		}
	}

	// Find removed
	for key, oldComp := range oldMap {
		if _, exists := newMap[key]; !exists {
			diff.Removed = append(diff.Removed, oldComp)
		}
	}

	return diff
}

// HasChanges returns true if the diff contains any changes.
func (d *SBOMDiff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// TotalChanges returns the total number of changed components.
func (d *SBOMDiff) TotalChanges() int {
	return len(d.Added) + len(d.Removed) + len(d.Changed)
}

// Summary returns a human-readable summary of the diff.
func (d *SBOMDiff) Summary() string {
	parts := make([]string, 0, 3)
	if len(d.Added) > 0 {
		parts = append(parts, fmt.Sprintf("%d added", len(d.Added)))
	}
	if len(d.Removed) > 0 {
		parts = append(parts, fmt.Sprintf("%d removed", len(d.Removed)))
	}
	if len(d.Changed) > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", len(d.Changed)))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("No changes (%d components unchanged)", d.Unchanged)
	}
	return strings.Join(parts, ", ")
}

// SortComponentsByName sorts SBOM components alphabetically by name.
func SortComponentsByName(components []*SBOMComponent) {
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})
}

// SortComponentsByRisk sorts SBOM components by associated risk score (descending).
func SortComponentsByRisk(components []*SBOMComponent, nvdData *NVDCPEData) []*RiskScore {
	scores := ScoreComponents(components, nvdData)
	SortByRisk(scores)
	return scores
}

// FilterComponentsByEcosystem filters components by ecosystem.
func FilterComponentsByEcosystem(components []*SBOMComponent, ecosystem Ecosystem) []*SBOMComponent {
	var result []*SBOMComponent
	for _, c := range components {
		if c.PURL != nil && c.PURL.Ecosystem() == ecosystem {
			result = append(result, c)
		}
	}
	return result
}

// FilterComponentsByType filters components by type (library, application, framework, etc.).
func FilterComponentsByType(components []*SBOMComponent, compType string) []*SBOMComponent {
	var result []*SBOMComponent
	for _, c := range components {
		if strings.EqualFold(c.Type, compType) {
			result = append(result, c)
		}
	}
	return result
}

// DeduplicateComponents removes duplicate components from a slice.
//
// Duplicates are identified by PURL (preferred) or CPE. The first occurrence is kept.
func DeduplicateComponents(components []*SBOMComponent) []*SBOMComponent {
	seen := make(map[string]bool)
	var result []*SBOMComponent
	for _, c := range components {
		key := componentKey(c)
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}

// EnrichComponentWithPedigree adds pedigree information to a component.
func EnrichComponentWithPedigree(component *SBOMComponent, pedigree *SBOMPedigree) {
	if component.Properties == nil {
		component.Properties = make(map[string]string)
	}
	component.Properties["cpe:hasPedigree"] = "true"
}

// EnrichComponentWithEvidence adds forensic evidence to a component.
func EnrichComponentWithEvidence(component *SBOMComponent, evidence []*SBOMEvidence) {
	if component.Properties == nil {
		component.Properties = make(map[string]string)
	}
	for i, e := range evidence {
		component.Properties[fmt.Sprintf("cpe:evidence:%d:field", i)] = e.Field
		component.Properties[fmt.Sprintf("cpe:evidence:%d:value", i)] = e.Value
	}
}

// SetComponentCopyright sets the copyright information for a component.
func SetComponentCopyright(component *SBOMComponent, copyright string) {
	if component.Properties == nil {
		component.Properties = make(map[string]string)
	}
	component.Properties["cpe:copyright"] = copyright
}

// componentKey generates a unique key for a component for deduplication.
// Prefers PURL, falls back to CPE, then name@version.
func componentKey(c *SBOMComponent) string {
	if c.PURL != nil && c.PURL.IsValid() {
		return "purl:" + c.PURL.String()
	}
	if c.CPE != nil && c.CPE.Cpe23 != "" {
		return "cpe:" + c.CPE.Cpe23
	}
	if c.BomRef != "" {
		return "ref:" + c.BomRef
	}
	return fmt.Sprintf("name:%s", c.Name)
}

// NewSBOMEvidence creates a new evidence entry.
func NewSBOMEvidence(field, value string, confidence float64) *SBOMEvidence {
	return &SBOMEvidence{
		Field:      field,
		Value:      value,
		Confidence: confidence,
	}
}

// NewSBOMPedigree creates a new empty pedigree.
func NewSBOMPedigree() *SBOMPedigree {
	return &SBOMPedigree{
		Ancestors:   make([]*SBOMComponent, 0),
		Descendants: make([]*SBOMComponent, 0),
		Variants:    make([]*SBOMComponent, 0),
		Commits:     make([]*SBOMCommit, 0),
		Patches:     make([]*SBOMPatch, 0),
	}
}

// AddAncestor adds an ancestor component to the pedigree.
func (p *SBOMPedigree) AddAncestor(component *SBOMComponent) {
	p.Ancestors = append(p.Ancestors, component)
}

// AddCommit adds a VCS commit to the pedigree.
func (p *SBOMPedigree) AddCommit(uid, url, message string) {
	p.Commits = append(p.Commits, &SBOMCommit{
		UID:     uid,
		URL:     url,
		Message: message,
	})
}

// ValidateSBOM performs basic validation on an SBOM document.
//
// Checks for required fields, component consistency, and dependency integrity.
func ValidateSBOM(sbom *SBOM) []string {
	var issues []string

	if sbom == nil {
		return []string{"SBOM is nil"}
	}

	if sbom.Format == SBOMFormatUnknown {
		issues = append(issues, "SBOM format is unknown")
	}

	if sbom.Name == "" {
		issues = append(issues, "SBOM name is empty")
	}

	// Check component references
	refs := make(map[string]bool)
	for _, c := range sbom.Components {
		if c.BomRef == "" {
			issues = append(issues, fmt.Sprintf("component %s has empty BomRef", c.Name))
		} else {
			refs[c.BomRef] = true
		}
	}

	// Check dependency references
	for _, d := range sbom.Dependencies {
		if d.Ref != "" && !refs[d.Ref] {
			issues = append(issues, fmt.Sprintf("dependency ref %s does not match any component", d.Ref))
		}
		for _, dep := range d.DependsOn {
			if dep != "" && !refs[dep] {
				issues = append(issues, fmt.Sprintf("dependency target %s does not match any component", dep))
			}
		}
	}

	return issues
}

// UpdateSBOMTimestamp updates the SBOM metadata timestamp to now.
func UpdateSBOMTimestamp(sbom *SBOM) {
	now := time.Now()
	sbom.CreatedAt = now
	if sbom.Metadata != nil {
		sbom.Metadata.Timestamp = now
	}
}
