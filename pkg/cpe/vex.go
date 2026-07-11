package cpeskills

import (
	"encoding/json"
	"fmt"
	"time"
)

// VEXStatus represents the exploitability status of a vulnerability in a specific product context.
//
// Based on the CycloneDX VEX extension and CSAF VEX profile.
type VEXStatus string

const (
	// VEXNotAffected — the vulnerability does not affect this product
	VEXNotAffected VEXStatus = "not_affected"

	// VEXAffected — the vulnerability affects this product
	VEXAffected VEXStatus = "affected"

	// VEXFixed — the vulnerability has been fixed in this product version
	VEXFixed VEXStatus = "fixed"

	// VEXUnderInvestigation — it is not yet known whether the vulnerability affects this product
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// VEXJustification provides the reason why a product is not affected.
//
// Defined by CSAF VEX and CycloneDX VEX specifications.
type VEXJustification string

const (
	// VEXComponentNotPresent — the vulnerable component is not included in the product
	VEXComponentNotPresent VEXJustification = "component_not_present"

	// VEXVulnerableCodeNotPresent — the vulnerable code is not present
	VEXVulnerableCodeNotPresent VEXJustification = "vulnerable_code_not_present"

	// VEXVulnerableCodeNotInExecutePath — the vulnerable code cannot be reached
	VEXVulnerableCodeNotInExecutePath VEXJustification = "vulnerable_code_not_in_execute_path"

	// VEXVulnerableCodeCannotBeControlledByAdversary — the vulnerable code cannot be exploited
	VEXVulnerableCodeCannotBeControlledByAdversary VEXJustification = "vulnerable_code_cannot_be_controlled_by_adversary"

	// VEXInlineMitigationsExist — mitigations are already in place
	VEXInlineMitigationsExist VEXJustification = "inline_mitigations_already_exist"
)

// VEXStatement represents a single VEX (Vulnerability Exploitability eXchange) statement.
//
// A VEX statement declares the exploitability status of a specific vulnerability
// in the context of a specific product. It is the core unit of a VEX document.
type VEXStatement struct {
	// ID unique identifier for this VEX statement
	ID string `json:"id"`

	// VulnerabilityID the vulnerability identifier (CVE, GHSA, etc.)
	VulnerabilityID string `json:"vulnerabilityId"`

	// VulnerabilityDescription human-readable description of the vulnerability
	VulnerabilityDescription string `json:"vulnerabilityDescription,omitempty"`

	// Status the exploitability status
	Status VEXStatus `json:"status"`

	// Justification reason for not_affected status
	Justification VEXJustification `json:"justification,omitempty"`

	// ProductID identifies the product this statement applies to (CPE URI or PURL)
	ProductID string `json:"productId"`

	// ProductName human-readable product name
	ProductName string `json:"productName,omitempty"`

	// ProductVersion the product version this statement applies to
	ProductVersion string `json:"productVersion,omitempty"`

	// ImpactStatement human-readable impact assessment
	ImpactStatement string `json:"impactStatement,omitempty"`

	// ActionStatement recommended action for affected products
	ActionStatement string `json:"actionStatement,omitempty"`

	// ActionStatementTimestamp when the action statement was last updated
	ActionStatementTimestamp time.Time `json:"actionStatementTimestamp,omitempty"`

	// LastUpdated when this VEX statement was last updated
	LastUpdated time.Time `json:"lastUpdated"`

	// Source who issued this VEX statement (vendor, researcher, etc.)
	Source string `json:"source,omitempty"`

	// SourceURL URL to the original VEX statement source
	SourceURL string `json:"sourceUrl,omitempty"`

	// Metadata additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// VEXDocument represents a complete VEX document containing multiple statements.
//
// Compatible with CSAF VEX profile and CycloneDX VEX extension.
type VEXDocument struct {
	// Format the VEX format: "csaf", "cyclonedx", "openvex"
	Format string `json:"format"`

	// ID unique identifier for this VEX document
	ID string `json:"id"`

	// Author who created this VEX document
	Author string `json:"author"`

	// AuthorRole role of the author (vendor, coordinator, etc.)
	AuthorRole string `json:"authorRole,omitempty"`

	// Timestamp when this VEX document was created
	Timestamp time.Time `json:"timestamp"`

	// LastUpdated when this VEX document was last updated
	LastUpdated time.Time `json:"lastUpdated"`

	// Version document version
	Version int `json:"version"`

	// Title document title
	Title string `json:"title,omitempty"`

	// ProductID the product this VEX document describes
	ProductID string `json:"productId"`

	// ProductName human-readable product name
	ProductName string `json:"productName"`

	// ProductVersion the product version
	ProductVersion string `json:"productVersion,omitempty"`

	// Supplier the product supplier
	Supplier string `json:"supplier,omitempty"`

	// Statements VEX statements in this document
	Statements []*VEXStatement `json:"statements"`
}

// NewVEXDocument creates a new VEX document.
func NewVEXDocument(format, productID, productName, author string) *VEXDocument {
	now := time.Now()
	return &VEXDocument{
		Format:       format,
		ID:           generateVEXID(),
		Author:       author,
		Timestamp:    now,
		LastUpdated:  now,
		Version:      1,
		ProductID:    productID,
		ProductName:  productName,
		Statements:   make([]*VEXStatement, 0),
	}
}

// AddStatement adds a VEX statement to the document.
func (d *VEXDocument) AddStatement(stmt *VEXStatement) {
	if stmt.ID == "" {
		stmt.ID = generateVEXStatementID()
	}
	if stmt.LastUpdated.IsZero() {
		stmt.LastUpdated = time.Now()
	}
	d.Statements = append(d.Statements, stmt)
	d.LastUpdated = time.Now()
}

// NewVEXStatement creates a new VEX statement.
func NewVEXStatement(vulnerabilityID, productID string, status VEXStatus) *VEXStatement {
	return &VEXStatement{
		ID:              generateVEXStatementID(),
		VulnerabilityID: vulnerabilityID,
		ProductID:       productID,
		Status:          status,
		LastUpdated:     time.Now(),
	}
}

// ToJSON serializes the VEX document to JSON.
func (d *VEXDocument) ToJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// ParseVEXDocument parses a VEX document from JSON.
func ParseVEXDocument(data []byte) (*VEXDocument, error) {
	var doc VEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse VEX document: %w", err)
	}
	return &doc, nil
}

// FindStatement finds a VEX statement by vulnerability ID.
func (d *VEXDocument) FindStatement(vulnerabilityID string) *VEXStatement {
	for _, stmt := range d.Statements {
		if stmt.VulnerabilityID == vulnerabilityID {
			return stmt
		}
	}
	return nil
}

// GetAffectedStatements returns all statements with "affected" status.
func (d *VEXDocument) GetAffectedStatements() []*VEXStatement {
	var result []*VEXStatement
	for _, stmt := range d.Statements {
		if stmt.Status == VEXAffected {
			result = append(result, stmt)
		}
	}
	return result
}

// GetNotAffectedStatements returns all statements with "not_affected" status.
func (d *VEXDocument) GetNotAffectedStatements() []*VEXStatement {
	var result []*VEXStatement
	for _, stmt := range d.Statements {
		if stmt.Status == VEXNotAffected {
			result = append(result, stmt)
		}
	}
	return result
}

// StatementCount returns the number of statements in the document.
func (d *VEXDocument) StatementCount() int {
	return len(d.Statements)
}

// MergeVEXDocuments merges multiple VEX documents into one.
//
// Statements are deduplicated by vulnerability ID (last wins).
func MergeVEXDocuments(docs []*VEXDocument) *VEXDocument {
	if len(docs) == 0 {
		return nil
	}

	merged := &VEXDocument{
		Format:      docs[0].Format,
		ID:          generateVEXID(),
		Author:      docs[0].Author,
		Timestamp:   time.Now(),
		LastUpdated: time.Now(),
		Version:     1,
		ProductID:   docs[0].ProductID,
		ProductName: docs[0].ProductName,
		Statements:  make([]*VEXStatement, 0),
	}

	seen := make(map[string]bool)
	// Process in reverse so later documents take precedence
	for i := len(docs) - 1; i >= 0; i-- {
		for _, stmt := range docs[i].Statements {
			if !seen[stmt.VulnerabilityID] {
				seen[stmt.VulnerabilityID] = true
				merged.Statements = append(merged.Statements, stmt)
			}
		}
	}

	// Reverse statements to original order
	for i, j := 0, len(merged.Statements)-1; i < j; i, j = i+1, j-1 {
		merged.Statements[i], merged.Statements[j] = merged.Statements[j], merged.Statements[i]
	}

	return merged
}

// GenerateVEXFromFindings generates VEX statements from vulnerability findings.
//
// This bridges the vulnerability detection pipeline with VEX output,
// allowing automated VEX generation from scan results.
func GenerateVEXFromFindings(component *SBOMComponent, findings []*VulnerabilityFinding, productID string) *VEXDocument {
	doc := NewVEXDocument("cyclonedx", productID, component.Name, "cpe-skills")
	doc.ProductVersion = component.Version

	for _, finding := range findings {
		vulnID := "unknown"
		description := ""
		if finding.CVE != nil {
			vulnID = finding.CVE.CVEID
			description = finding.CVE.Description
		} else if finding.OSV != nil {
			vulnID = finding.OSV.ID
			description = finding.OSV.Summary
		}

		status := VEXAffected
		if finding.FixAvailable {
			status = VEXFixed
		}

		stmt := NewVEXStatement(vulnID, productID, status)
		stmt.VulnerabilityDescription = description
		stmt.ProductName = component.Name
		stmt.ProductVersion = component.Version

		if finding.FixedVersion != "" {
			stmt.ActionStatement = fmt.Sprintf("Upgrade to version %s or later.", finding.FixedVersion)
		}

		doc.AddStatement(stmt)
	}

	return doc
}

// ApplyVEXToFindings applies VEX statements to vulnerability findings,
// filtering out or adjusting findings based on VEX status.
//
// Returns the filtered list of findings that remain actionable.
func ApplyVEXToFindings(findings []*VulnerabilityFinding, doc *VEXDocument) []*VulnerabilityFinding {
	if doc == nil {
		return findings
	}

	var result []*VulnerabilityFinding
	for _, finding := range findings {
		vulnID := ""
		if finding.CVE != nil {
			vulnID = finding.CVE.CVEID
		} else if finding.OSV != nil {
			vulnID = finding.OSV.ID
		}

		stmt := doc.FindStatement(vulnID)
		if stmt == nil {
			// No VEX statement — keep the finding
			result = append(result, finding)
			continue
		}

		switch stmt.Status {
		case VEXNotAffected:
			// Filter out — product is not affected
			continue
		case VEXFixed:
			// Mark as fixed
			finding.FixAvailable = true
			result = append(result, finding)
		case VEXUnderInvestigation:
			// Keep but mark
			result = append(result, finding)
		default:
			// Affected — keep
			result = append(result, finding)
		}
	}

	return result
}

// generateVEXID generates a unique VEX document ID.
func generateVEXID() string {
	return fmt.Sprintf("VEX-%s", generateUUIDv4())
}

// generateVEXStatementID generates a unique VEX statement ID.
func generateVEXStatementID() string {
	return fmt.Sprintf("VEXSTMT-%s", generateUUIDv4())
}
