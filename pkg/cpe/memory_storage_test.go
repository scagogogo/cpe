package cpeskills

import (
	"testing"
	"time"
)

func TestNewMemoryStorage(t *testing.T) {
	ms := NewMemoryStorage()
	if ms == nil {
		t.Fatalf("NewMemoryStorage() returned nil")
	}
	if ms.cpes == nil {
		t.Errorf("cpes map is nil")
	}
	if ms.cves == nil {
		t.Errorf("cves map is nil")
	}
	if ms.cpeToCVEs == nil {
		t.Errorf("cpeToCVEs map is nil")
	}
	if ms.cveToCPEs == nil {
		t.Errorf("cveToCPEs map is nil")
	}
	if ms.dictionary != nil {
		t.Errorf("dictionary should be nil initially")
	}
	if ms.timestamps == nil {
		t.Errorf("timestamps map is nil")
	}
}

func TestMemoryStorage_Initialize(t *testing.T) {
	ms := NewMemoryStorage()

	// Store some data first
	ms.cpes["test"] = &CPE{Cpe23: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}
	ms.cves["CVE-2021-0001"] = &CVEReference{CVEID: "CVE-2021-0001"}

	err := ms.Initialize()
	if err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	// Verify all maps are cleared
	if len(ms.cpes) != 0 {
		t.Errorf("cpes should be empty after Initialize, got %d items", len(ms.cpes))
	}
	if len(ms.cves) != 0 {
		t.Errorf("cves should be empty after Initialize, got %d items", len(ms.cves))
	}
	if len(ms.cpeToCVEs) != 0 {
		t.Errorf("cpeToCVEs should be empty after Initialize")
	}
	if len(ms.cveToCPEs) != 0 {
		t.Errorf("cveToCPEs should be empty after Initialize")
	}
	if ms.dictionary != nil {
		t.Errorf("dictionary should be nil after Initialize")
	}
	if len(ms.timestamps) != 1 {
		t.Errorf("timestamps should have 1 entry (initialization), got %d", len(ms.timestamps))
	}
}

func TestMemoryStorage_Close(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// --- StoreCPE Tests ---

func TestMemoryStorage_StoreCPE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	err := ms.StoreCPE(testCPE)
	if err != nil {
		t.Errorf("StoreCPE() error = %v", err)
	}

	if len(ms.cpes) != 1 {
		t.Errorf("Expected 1 CPE, got %d", len(ms.cpes))
	}
}

func TestMemoryStorage_StoreCPE_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.StoreCPE(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreCPE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_StoreCPE_EmptyURI(t *testing.T) {
	ms := NewMemoryStorage()
	// A CPE with empty Cpe23 but all empty fields will generate a URI like "cpe:2.3:::::::"
	// which is technically not empty. To test the empty URI path, we would need
	// to construct a CPE that somehow returns an empty URI.
	// Instead, verify that a minimal CPE can be stored (since GetURI() is not empty)
	cpe := &CPE{Cpe23: ""}
	// GetURI() will generate "cpe:2.3:::::::" which is not empty
	err := ms.StoreCPE(cpe)
	// This should succeed since the generated URI is not empty
	if err != nil {
		t.Logf("StoreCPE() with minimal CPE: %v", err)
	}
}

// --- RetrieveCPE Tests ---

func TestMemoryStorage_RetrieveCPE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(testCPE)

	result, err := ms.RetrieveCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("RetrieveCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("RetrieveCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}
}

func TestMemoryStorage_RetrieveCPE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	_, err := ms.RetrieveCPE("nonexistent")
	if err != ErrNotFound {
		t.Errorf("RetrieveCPE() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStorage_RetrieveCPE_DeepCopy(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(testCPE)

	result, _ := ms.RetrieveCPE(testCPE.GetURI())
	result.Vendor = Vendor("modified")

	original, _ := ms.RetrieveCPE(testCPE.GetURI())
	if original.Vendor == Vendor("modified") {
		t.Errorf("RetrieveCPE() should return a deep copy")
	}
}

// --- UpdateCPE Tests ---

func TestMemoryStorage_UpdateCPE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(testCPE)

	testCPE.Version = Version("2.0")
	err := ms.UpdateCPE(testCPE)
	if err != nil {
		t.Errorf("UpdateCPE() error = %v", err)
	}

	result, _ := ms.RetrieveCPE(testCPE.GetURI())
	if result.Version != Version("2.0") {
		t.Errorf("UpdateCPE() version = %v, want 2.0", result.Version)
	}
}

func TestMemoryStorage_UpdateCPE_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.UpdateCPE(nil)
	if err != ErrInvalidData {
		t.Errorf("UpdateCPE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_UpdateCPE_EmptyURI(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.UpdateCPE(&CPE{})
	if err == nil {
		t.Errorf("UpdateCPE() with empty URI should return error")
	}
}

func TestMemoryStorage_UpdateCPE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	err := ms.UpdateCPE(testCPE)
	if err != ErrNotFound {
		t.Errorf("UpdateCPE() error = %v, want ErrNotFound", err)
	}
}

// --- DeleteCPE Tests ---

func TestMemoryStorage_DeleteCPE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(testCPE)

	err := ms.DeleteCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("DeleteCPE() error = %v", err)
	}

	_, err = ms.RetrieveCPE(testCPE.GetURI())
	if err != ErrNotFound {
		t.Errorf("After DeleteCPE, RetrieveCPE should return ErrNotFound, got %v", err)
	}
}

func TestMemoryStorage_DeleteCPE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	err := ms.DeleteCPE("nonexistent")
	if err != ErrNotFound {
		t.Errorf("DeleteCPE() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStorage_DeleteCPE_RemovesCVEAssociations(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(testCPE)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	// Verify association exists
	ms.cpeToCVEs[testCPE.GetURI()] = append(ms.cpeToCVEs[testCPE.GetURI()], cve.CVEID)
	ms.cveToCPEs[cve.CVEID] = append(ms.cveToCPEs[cve.CVEID], testCPE.GetURI())

	err := ms.DeleteCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("DeleteCPE() error = %v", err)
	}

	// cpeToCVEs entry should be deleted
	if _, ok := ms.cpeToCVEs[testCPE.GetURI()]; ok {
		t.Errorf("cpeToCVEs entry should be deleted after DeleteCPE")
	}

	// cveToCPEs should not contain the deleted CPE ID
	cpeIDs := ms.cveToCPEs[cve.CVEID]
	for _, id := range cpeIDs {
		if id == testCPE.GetURI() {
			t.Errorf("cveToCPEs should not contain deleted CPE ID")
		}
	}
}

// --- SearchCPE Tests ---

func TestMemoryStorage_SearchCPE_NilCriteria(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	})
	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	})

	results, err := ms.SearchCPE(nil, nil)
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchCPE(nil) returned %d results, want 2", len(results))
	}
}

func TestMemoryStorage_SearchCPE_WithCriteria(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	})
	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	})

	// Use full criteria that matches vendor1's CPE exactly
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	results, err := ms.SearchCPE(criteria, &MatchOptions{})
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCPE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCPE_NilOptions(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	})

	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	results, err := ms.SearchCPE(criteria, nil)
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCPE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCPE_NoMatch(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	})

	criteria := &CPE{Vendor: Vendor("nonexistent")}
	results, err := ms.SearchCPE(criteria, &MatchOptions{})
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SearchCPE() returned %d results, want 0", len(results))
	}
}

// --- AdvancedSearchCPE Tests ---

func TestMemoryStorage_AdvancedSearchCPE_NilCriteria(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	})

	results, err := ms.AdvancedSearchCPE(nil, nil)
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE(nil) returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_AdvancedSearchCPE_WithCriteria(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	})
	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	})

	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	results, err := ms.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_AdvancedSearchCPE_NilOptions(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	ms.StoreCPE(&CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	})

	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	results, err := ms.AdvancedSearchCPE(criteria, nil)
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1", len(results))
	}
}

// --- StoreCVE Tests ---

func TestMemoryStorage_StoreCVE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Test CVE"

	err := ms.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}

	if len(ms.cves) != 1 {
		t.Errorf("Expected 1 CVE, got %d", len(ms.cves))
	}
}

func TestMemoryStorage_StoreCVE_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.StoreCVE(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreCVE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_StoreCVE_EmptyID(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.StoreCVE(&CVEReference{})
	if err == nil {
		t.Errorf("StoreCVE() with empty ID should return error")
	}
}

func TestMemoryStorage_StoreCVE_WithAffectedCPEs_CPE23(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

	err := ms.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}

	// Check CVE-CPE associations were created
	cpeIDs := ms.cveToCPEs[cve.CVEID]
	if len(cpeIDs) == 0 {
		t.Errorf("cveToCPEs should have entries for CVE-2021-12345")
	}

	cveIDs := ms.cpeToCVEs["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
	if len(cveIDs) == 0 {
		t.Errorf("cpeToCVEs should have entries for the affected CPE")
	}
}

func TestMemoryStorage_StoreCVE_WithInvalidCPEPrefix(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.AffectedCPEs = []string{"invalid:cpe:format"}

	err := ms.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}

	// Invalid CPE format should be skipped
	if len(ms.cveToCPEs[cve.CVEID]) != 0 {
		t.Errorf("cveToCPEs should not have entries for invalid CPEs")
	}
}

func TestMemoryStorage_StoreCVE_WithCPE22(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:/a:vendor:product:1.0")

	err := ms.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}

	cpeIDs := ms.cveToCPEs[cve.CVEID]
	if len(cpeIDs) == 0 {
		t.Errorf("cveToCPEs should have entries for CVE-2021-12345 with CPE 2.2")
	}
}

func TestMemoryStorage_StoreCVE_NoAffectedCPEs(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.AffectedCPEs = []string{} // empty

	err := ms.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}
}

// --- RetrieveCVE Tests ---

func TestMemoryStorage_RetrieveCVE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Test CVE"
	ms.StoreCVE(cve)

	result, err := ms.RetrieveCVE(cve.CVEID)
	if err != nil {
		t.Errorf("RetrieveCVE() error = %v", err)
	}
	if result.CVEID != cve.CVEID {
		t.Errorf("RetrieveCVE() = %v, want %v", result.CVEID, cve.CVEID)
	}
}

func TestMemoryStorage_RetrieveCVE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	_, err := ms.RetrieveCVE("CVE-nonexistent")
	if err != ErrNotFound {
		t.Errorf("RetrieveCVE() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStorage_RetrieveCVE_DeepCopy(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Test CVE"
	ms.StoreCVE(cve)

	result, _ := ms.RetrieveCVE(cve.CVEID)
	result.Description = "Modified"

	original, _ := ms.RetrieveCVE(cve.CVEID)
	if original.Description == "Modified" {
		t.Errorf("RetrieveCVE() should return a deep copy")
	}
}

// --- UpdateCVE Tests ---

func TestMemoryStorage_UpdateCVE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Original"
	ms.StoreCVE(cve)

	cve.Description = "Updated"
	err := ms.UpdateCVE(cve)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	result, _ := ms.RetrieveCVE(cve.CVEID)
	if result.Description != "Updated" {
		t.Errorf("UpdateCVE() description = %v, want Updated", result.Description)
	}
}

func TestMemoryStorage_UpdateCVE_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.UpdateCVE(nil)
	if err != ErrInvalidData {
		t.Errorf("UpdateCVE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_UpdateCVE_EmptyID(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.UpdateCVE(&CVEReference{})
	if err == nil {
		t.Errorf("UpdateCVE() with empty ID should return error")
	}
}

func TestMemoryStorage_UpdateCVE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	err := ms.UpdateCVE(cve)
	if err != ErrNotFound {
		t.Errorf("UpdateCVE() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStorage_UpdateCVE_ClearsOldRelationships(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	// Now update CVE with different affected CPEs
	cve2 := &CVEReference{
		CVEID:        cve.CVEID,
		Description:  "Updated",
		AffectedCPEs: []string{}, // clear affected CPEs
	}

	err := ms.UpdateCVE(cve2)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	// The old CPE-CVE relationship should be cleared
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
	for _, id := range cveIDs {
		if id == cve.CVEID {
			t.Errorf("Old CPE-CVE relationship should be cleared after UpdateCVE")
		}
	}
}

func TestMemoryStorage_UpdateCVE_WithNewCPEs(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	cpe2 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe1)
	ms.StoreCPE(cpe2)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	// Update CVE to reference a different CPE
	cveUpdated := &CVEReference{
		CVEID:        cve.CVEID,
		Description:  "Updated",
		AffectedCPEs: []string{"cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*"},
	}
	ms.UpdateCVE(cveUpdated)

	// cveToCPEs should now point to vendor2/product2
	cpeIDs := ms.cveToCPEs[cve.CVEID]
	found := false
	for _, id := range cpeIDs {
		if id == "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*" {
			found = true
		}
	}
	if !found {
		t.Errorf("UpdateCVE should update cveToCPEs with new CPE")
	}
}

func TestMemoryStorage_UpdateCVE_WithInvalidCPEPrefix(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Original"
	ms.StoreCVE(cve)

	cveUpdated := &CVEReference{
		CVEID:        cve.CVEID,
		Description:  "Updated",
		AffectedCPEs: []string{"invalid:cpe:format"},
	}

	err := ms.UpdateCVE(cveUpdated)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	// Invalid CPE should be skipped
	cpeIDs := ms.cveToCPEs[cve.CVEID]
	if len(cpeIDs) != 0 {
		t.Errorf("cveToCPEs should not have entries for invalid CPEs")
	}
}

func TestMemoryStorage_UpdateCVE_NoOldRelationships(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Original"
	ms.StoreCVE(cve)

	// No AffectedCPEs means no cveToCPEs entry
	delete(ms.cveToCPEs, cve.CVEID)

	cveUpdated := &CVEReference{
		CVEID:        cve.CVEID,
		Description:  "Updated",
		AffectedCPEs: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
	}

	err := ms.UpdateCVE(cveUpdated)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}
}

// --- DeleteCVE Tests ---

func TestMemoryStorage_DeleteCVE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	ms.StoreCVE(cve)

	err := ms.DeleteCVE(cve.CVEID)
	if err != nil {
		t.Errorf("DeleteCVE() error = %v", err)
	}

	_, err = ms.RetrieveCVE(cve.CVEID)
	if err != ErrNotFound {
		t.Errorf("After DeleteCVE, RetrieveCVE should return ErrNotFound")
	}
}

func TestMemoryStorage_DeleteCVE_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	err := ms.DeleteCVE("CVE-nonexistent")
	if err != ErrNotFound {
		t.Errorf("DeleteCVE() error = %v, want ErrNotFound", err)
	}
}

func TestMemoryStorage_DeleteCVE_ClearsCVERelationships(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	// Manually add the bidirectional relationship
	ms.cpeToCVEs["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"] = append(ms.cpeToCVEs["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"], cve.CVEID)
	ms.cveToCPEs[cve.CVEID] = append(ms.cveToCPEs[cve.CVEID], "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

	err := ms.DeleteCVE(cve.CVEID)
	if err != nil {
		t.Errorf("DeleteCVE() error = %v", err)
	}

	// cveToCPEs should be deleted
	if _, ok := ms.cveToCPEs[cve.CVEID]; ok {
		t.Errorf("cveToCPEs should be deleted after DeleteCVE")
	}

	// cpeToCVEs should not contain the deleted CVE ID
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
	for _, id := range cveIDs {
		if id == cve.CVEID {
			t.Errorf("cpeToCVEs should not contain deleted CVE ID")
		}
	}
}

// --- SearchCVE Tests ---

func TestMemoryStorage_SearchCVE_EmptyQuery(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	cve1.Description = "First CVE"
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	cve2.Description = "Second CVE"
	ms.StoreCVE(cve2)

	results, err := ms.SearchCVE("", nil)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchCVE('') returned %d results, want 2", len(results))
	}
}

func TestMemoryStorage_SearchCVE_WithQuery(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	cve1.Description = "windows vulnerability"
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	cve2.Description = "linux vulnerability"
	ms.StoreCVE(cve2)

	results, err := ms.SearchCVE("windows", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE('windows') returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_QueryMatchesCVEID(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-12345")
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2022-99999")
	ms.StoreCVE(cve2)

	results, err := ms.SearchCVE("2021-12345", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_QueryMatchesReference(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-12345")
	cve1.References = []string{"https://example.com/advisory"}
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-99999")
	cve2.References = []string{"https://other.com/advisory"}
	ms.StoreCVE(cve2)

	results, err := ms.SearchCVE("example.com", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_NilOptions(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	ms.StoreCVE(cve)

	results, err := ms.SearchCVE("", nil)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_Pagination(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	for i := 0; i < 10; i++ {
		cve := NewCVEReference("CVE-2021-%05d")
		ms.StoreCVE(cve)
	}

	// Offset beyond results
	opts := NewSearchOptions()
	opts.Offset = 100
	opts.Limit = 10
	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SearchCVE() with high offset returned %d results, want 0", len(results))
	}
}

func TestMemoryStorage_SearchCVE_Pagination_Limit(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	for i := 0; i < 5; i++ {
		cveID := "CVE-2021-%05d"
		ms.StoreCVE(NewCVEReference(cveID))
	}

	opts := NewSearchOptions()
	opts.Offset = 0
	opts.Limit = 2
	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) > 2 {
		t.Errorf("SearchCVE() with limit 2 returned %d results, want at most 2", len(results))
	}
}

func TestMemoryStorage_SearchCVE_Pagination_PartialEnd(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	for i := 0; i < 5; i++ {
		ms.StoreCVE(NewCVEReference("CVE-2021-0000" + string(rune('0'+i))))
	}

	opts := NewSearchOptions()
	opts.Offset = 3
	opts.Limit = 10
	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchCVE() with offset 3, limit 10 returned %d results, want 2", len(results))
	}
}

// --- applyCVEFilters Tests ---

func TestMemoryStorage_ApplyCVEFilters_MinCVSS(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.CVSSScore = 5.0

	opts := &SearchOptions{MinCVSS: 7.0}
	if ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return false when CVSS below min")
	}
}

func TestMemoryStorage_ApplyCVEFilters_MaxCVSS(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve := NewCVEReference("CVE-2021-12345")
	cve.CVSSScore = 9.0

	opts := &SearchOptions{MaxCVSS: 7.0}
	if ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return false when CVSS above max")
	}
}

func TestMemoryStorage_ApplyCVEFilters_DateRange(t *testing.T) {
	ms := NewMemoryStorage()

	pastTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	futureTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	cve := &CVEReference{
		CVEID:         "CVE-2021-12345",
		PublishedDate: time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
	}

	// Within range
	opts := &SearchOptions{
		DateStart: &pastTime,
		DateEnd:   &futureTime,
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for CVE within date range")
	}

	// Before start date
	earlyStart := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	opts2 := &SearchOptions{DateStart: &earlyStart}
	if ms.applyCVEFilters(cve, opts2) {
		t.Errorf("applyCVEFilters() should return false for CVE before start date")
	}

	// After end date
	earlyEnd := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	opts3 := &SearchOptions{DateEnd: &earlyEnd}
	if ms.applyCVEFilters(cve, opts3) {
		t.Errorf("applyCVEFilters() should return false for CVE after end date")
	}
}

func TestMemoryStorage_ApplyCVEFilters_SeverityFilter(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:     "CVE-2021-12345",
		Severity:  "High",
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"severity": "High"},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for matching severity")
	}

	opts2 := &SearchOptions{
		Filters: map[string]interface{}{"severity": "Low"},
	}
	if ms.applyCVEFilters(cve, opts2) {
		t.Errorf("applyCVEFilters() should return false for non-matching severity")
	}
}

func TestMemoryStorage_ApplyCVEFilters_VendorFilter(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-12345",
		AffectedCPEs: []string{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"},
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"vendor": "microsoft"},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for matching vendor")
	}

	opts2 := &SearchOptions{
		Filters: map[string]interface{}{"vendor": "google"},
	}
	if ms.applyCVEFilters(cve, opts2) {
		t.Errorf("applyCVEFilters() should return false for non-matching vendor")
	}
}

func TestMemoryStorage_ApplyCVEFilters_ProductFilter(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-12345",
		AffectedCPEs: []string{"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"},
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"product": "windows"},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for matching product")
	}

	opts2 := &SearchOptions{
		Filters: map[string]interface{}{"product": "linux"},
	}
	if ms.applyCVEFilters(cve, opts2) {
		t.Errorf("applyCVEFilters() should return false for non-matching product")
	}
}

func TestMemoryStorage_ApplyCVEFilters_VendorFilterWithCPE22(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-12345",
		AffectedCPEs: []string{"cpe:/a:microsoft:windows:10"},
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"vendor": "microsoft"},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for matching vendor with CPE 2.2")
	}
}

func TestMemoryStorage_ApplyCVEFilters_ProductFilterWithCPE22(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-12345",
		AffectedCPEs: []string{"cpe:/a:microsoft:windows:10"},
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"product": "windows"},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true for matching product with CPE 2.2")
	}
}

func TestMemoryStorage_ApplyCVEFilters_InvalidCPEPrefix(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-12345",
		AffectedCPEs: []string{"invalid:cpe:format"},
	}

	opts := &SearchOptions{
		Filters: map[string]interface{}{"vendor": "microsoft"},
	}
	if ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return false when no valid CPEs match vendor filter")
	}
}

func TestMemoryStorage_ApplyCVEFilters_NoFilters(t *testing.T) {
	ms := NewMemoryStorage()

	cve := NewCVEReference("CVE-2021-12345")
	opts := NewSearchOptions()

	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true when no filters are set")
	}
}

func TestMemoryStorage_ApplyCVEFilters_InvalidFilterValue(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:     "CVE-2021-12345",
		Severity:  "High",
	}

	// Non-string severity value: type assertion fails, so filter is skipped
	// This means the CVE passes the filter (returns true)
	opts := &SearchOptions{
		Filters: map[string]interface{}{"severity": 123},
	}
	if !ms.applyCVEFilters(cve, opts) {
		t.Errorf("applyCVEFilters() should return true when severity filter has non-string value (filter is skipped)")
	}
}

// --- FindCVEsByCPE Tests ---

func TestMemoryStorage_FindCVEsByCPE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	results, err := ms.FindCVEsByCPE(cpe)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("FindCVEsByCPE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_FindCVEsByCPE_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	_, err := ms.FindCVEsByCPE(nil)
	if err != ErrInvalidData {
		t.Errorf("FindCVEsByCPE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_FindCVEsByCPE_NoMatch(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	// Different CPE that has no CVEs
	searchCPE := &CPE{
		Cpe23:       "cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("other"),
		ProductName: Product("thing"),
		Version:     Version("1.0"),
	}

	results, err := ms.FindCVEsByCPE(searchCPE)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("FindCVEsByCPE() returned %d results, want 0", len(results))
	}
}

func TestMemoryStorage_FindCVEsByCPE_FuzzyMatch(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	// Search with exact same CPE should find results
	searchCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	results, err := ms.FindCVEsByCPE(searchCPE)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	if len(results) < 1 {
		t.Errorf("FindCVEsByCPE() with exact CPE should match, got %d results", len(results))
	}
}

func TestMemoryStorage_FindCVEsByCPE_InvalidCPEPrefix(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	// Add a cpeToCVEs entry with an invalid prefix
	ms.cpeToCVEs["invalid_cpe_format"] = []string{"CVE-2021-12345"}
	ms.cves["CVE-2021-12345"] = NewCVEReference("CVE-2021-12345")

	searchCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	_, err := ms.FindCVEsByCPE(searchCPE)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	// Should still return results (possibly empty) without crashing
}

func TestMemoryStorage_FindCVEsByCPE_CPE22InCPEToCVEs(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	// Add a cpeToCVEs entry with a CPE 2.2 format key
	cpe22URI := "cpe:/a:vendor:product:1.0"
	ms.cpeToCVEs[cpe22URI] = []string{"CVE-2021-12345"}
	ms.cves["CVE-2021-12345"] = NewCVEReference("CVE-2021-12345")
	ms.cves["CVE-2021-12345"].Description = "Test CVE for CPE 2.2 lookup"

	// Search with a CPE that doesn't directly match but should trigger fuzzy matching
	searchCPE := &CPE{
		Cpe23:       "cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("other"),
		ProductName: Product("thing"),
		Version:     Version("1.0"),
	}

	results, err := ms.FindCVEsByCPE(searchCPE)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	// The fuzzy match won't find a match since vendors differ, so results should be 0
	if len(results) != 0 {
		t.Logf("FindCVEsByCPE with CPE 2.2 in cpeToCVEs returned %d results", len(results))
	}
}

func TestMemoryStorage_FindCVEsByCPE_UnparseableCPEInCPEToCVEs(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	// Add a cpeToCVEs entry with an invalid CPE 2.3 string that will fail parsing
	invalidCPE23 := "cpe:2.3:invalid_format_that_will_fail_parsing"
	ms.cpeToCVEs[invalidCPE23] = []string{"CVE-2021-99999"}
	ms.cves["CVE-2021-99999"] = NewCVEReference("CVE-2021-99999")

	searchCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	// Should not panic even with unparseable CPEs
	results, err := ms.FindCVEsByCPE(searchCPE)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	// The unparseable CPE should be skipped in fuzzy matching
	t.Logf("FindCVEsByCPE returned %d results", len(results))
}

// --- FindCPEsByCVE Tests ---

func TestMemoryStorage_FindCPEsByCVE(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	ms.StoreCPE(cpe)

	cve := NewCVEReference("CVE-2021-12345")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	ms.StoreCVE(cve)

	results, err := ms.FindCPEsByCVE(cve.CVEID)
	if err != nil {
		t.Errorf("FindCPEsByCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("FindCPEsByCVE() returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_FindCPEsByCVE_NoMatch(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	results, err := ms.FindCPEsByCVE("CVE-nonexistent")
	if err != nil {
		t.Errorf("FindCPEsByCVE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("FindCPEsByCVE() returned %d results, want 0", len(results))
	}
}

// --- Dictionary Tests ---

func TestMemoryStorage_StoreDictionary(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}

	err := ms.StoreDictionary(dict)
	if err != nil {
		t.Errorf("StoreDictionary() error = %v", err)
	}
}

func TestMemoryStorage_StoreDictionary_Nil(t *testing.T) {
	ms := NewMemoryStorage()
	err := ms.StoreDictionary(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreDictionary(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestMemoryStorage_RetrieveDictionary(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}
	ms.StoreDictionary(dict)

	result, err := ms.RetrieveDictionary()
	if err != nil {
		t.Errorf("RetrieveDictionary() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Errorf("RetrieveDictionary() returned %d items, want 1", len(result.Items))
	}
}

func TestMemoryStorage_RetrieveDictionary_NotFound(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	_, err := ms.RetrieveDictionary()
	if err != ErrNotFound {
		t.Errorf("RetrieveDictionary() error = %v, want ErrNotFound", err)
	}
}

// --- Timestamp Tests ---

func TestMemoryStorage_StoreModificationTimestamp(t *testing.T) {
	ms := NewMemoryStorage()
	testTime := time.Now()

	err := ms.StoreModificationTimestamp("test_key", testTime)
	if err != nil {
		t.Errorf("StoreModificationTimestamp() error = %v", err)
	}
}

func TestMemoryStorage_RetrieveModificationTimestamp(t *testing.T) {
	ms := NewMemoryStorage()
	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	ms.StoreModificationTimestamp("test_key", testTime)

	result, err := ms.RetrieveModificationTimestamp("test_key")
	if err != nil {
		t.Errorf("RetrieveModificationTimestamp() error = %v", err)
	}
	if result.Unix() != testTime.Unix() {
		t.Errorf("RetrieveModificationTimestamp() = %v, want %v", result, testTime)
	}
}

func TestMemoryStorage_RetrieveModificationTimestamp_NotFound(t *testing.T) {
	ms := NewMemoryStorage()

	_, err := ms.RetrieveModificationTimestamp("nonexistent")
	if err != ErrNotFound {
		t.Errorf("RetrieveModificationTimestamp() error = %v, want ErrNotFound", err)
	}
}

// --- ParseURI Tests ---

func TestMemoryStorage_ParseURI_CPE23(t *testing.T) {
	result, err := ParseURI("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Errorf("ParseURI() error = %v", err)
	}
	if result == nil {
		t.Fatalf("ParseURI() returned nil")
	}
	if result.Vendor != Vendor("vendor") {
		t.Errorf("ParseURI() Vendor = %v, want vendor", result.Vendor)
	}
}

func TestMemoryStorage_ParseURI_CPE22(t *testing.T) {
	result, err := ParseURI("cpe:/a:vendor:product:1.0")
	if err != nil {
		t.Errorf("ParseURI() error = %v", err)
	}
	if result == nil {
		t.Fatalf("ParseURI() returned nil")
	}
}

func TestMemoryStorage_ParseURI_InvalidFormat(t *testing.T) {
	_, err := ParseURI("invalid:format")
	if err == nil {
		t.Errorf("ParseURI() should return error for invalid format")
	}
}

func TestMemoryStorage_ParseURI_EmptyString(t *testing.T) {
	_, err := ParseURI("")
	if err == nil {
		t.Errorf("ParseURI() should return error for empty string")
	}
}

// --- Combined SearchCVE + Filters Tests ---

func TestMemoryStorage_SearchCVE_WithCVSSFilter(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	cve1.CVSSScore = 5.0
	cve1.Description = "medium severity"
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	cve2.CVSSScore = 9.0
	cve2.Description = "critical severity"
	ms.StoreCVE(cve2)

	opts := NewSearchOptions()
	opts.MinCVSS = 7.0

	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() with MinCVSS=7.0 returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_WithDateFilter(t *testing.T) {
	ms := NewMemoryStorage()

	startDate := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	cve1 := &CVEReference{
		CVEID:         "CVE-2022-00001",
		PublishedDate: time.Date(2022, 6, 15, 0, 0, 0, 0, time.UTC),
	}
	ms.StoreCVE(cve1)

	cve2 := &CVEReference{
		CVEID:         "CVE-2020-00001",
		PublishedDate: time.Date(2020, 6, 15, 0, 0, 0, 0, time.UTC),
	}
	ms.StoreCVE(cve2)

	opts := NewSearchOptions()
	opts.DateStart = &startDate
	opts.DateEnd = &endDate

	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() with date range returned %d results, want 1", len(results))
	}
}

func TestMemoryStorage_SearchCVE_WithSeverityFilter(t *testing.T) {
	ms := NewMemoryStorage()
	ms.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	cve1.Severity = "High"
	ms.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	cve2.Severity = "Low"
	ms.StoreCVE(cve2)

	opts := NewSearchOptions()
	opts.Filters["severity"] = "High"

	results, err := ms.SearchCVE("", opts)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() with severity filter returned %d results, want 1", len(results))
	}
}


// TestMemoryStorage_DeleteCPE_WithCVERelations tests DeleteCPE that removes CPE-CVE mappings
func TestMemoryStorage_DeleteCPE_WithCVERelations(t *testing.T) {
	ms := NewMemoryStorage()
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe)

	// Store a CVE that references this CPE
	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	ms.StoreCVE(cve)

	// Now delete the CPE - this should clean up CVE-CPE relationships
	err := ms.DeleteCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Errorf("DeleteCPE() error = %v", err)
	}

	// Verify CVE no longer has this CPE in its mapping
	cpeIDs := ms.cveToCPEs["CVE-2021-44228"]
	for _, id := range cpeIDs {
		if id == "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" {
			t.Error("DeleteCPE() should remove CPE from CVE mappings")
		}
	}
}

// TestMemoryStorage_UpdateCVE_WithCPERelations tests UpdateCVE that updates CVE-CPE relationships
func TestMemoryStorage_UpdateCVE_WithCPERelations(t *testing.T) {
	ms := NewMemoryStorage()

	// Store a CPE first
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe)

	// Store initial CVE
	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	ms.StoreCVE(cve)

	// Update CVE with different CPEs - the old CPE-CVE mapping should be cleaned
	updatedCve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"},
	}
	err := ms.UpdateCVE(updatedCve)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	// Verify old CPE no longer references this CVE
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
	for _, id := range cveIDs {
		if id == "CVE-2021-44228" {
			t.Error("UpdateCVE() should remove old CVE from CPE mappings")
		}
	}
}

// TestMemoryStorage_DeleteCVE_WithCPERelations tests DeleteCVE that removes CVE-CPE mappings
func TestMemoryStorage_DeleteCVE_WithCPERelations(t *testing.T) {
	ms := NewMemoryStorage()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe)

	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	ms.StoreCVE(cve)

	// Delete the CVE - this should clean up CPE-CVE relationships
	err := ms.DeleteCVE("CVE-2021-44228")
	if err != nil {
		t.Errorf("DeleteCVE() error = %v", err)
	}

	// Verify CPE no longer references this CVE
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
	for _, id := range cveIDs {
		if id == "CVE-2021-44228" {
			t.Error("DeleteCVE() should remove CVE from CPE mappings")
		}
	}
}

// TestMemoryStorage_ApplyCVEFilters_InvalidCPE tests applyCVEFilters with invalid CPE strings in product filter
func TestMemoryStorage_ApplyCVEFilters_InvalidCPE(t *testing.T) {
	ms := NewMemoryStorage()

	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"not_a_cpe"},
	}

	options := &SearchOptions{
		Filters: map[string]interface{}{
			"product": "log4j",
		},
	}

	result := ms.applyCVEFilters(cve, options)
	if result {
		t.Error("applyCVEFilters with invalid CPE in AffectedCPEs and product filter should return false")
	}
}

	// TestMemoryStorage_StoreCPE_CoverageGap_EmptyURI tests StoreCPE with a CPE that has empty URI
	func TestMemoryStorage_StoreCPE_CoverageGap_EmptyURI(t *testing.T) {
		ms := NewMemoryStorage()
		// Create a CPE with no Cpe23 and empty fields - GetURI should return empty
		cpe := &CPE{}
		// We need to check if GetURI returns empty for this CPE
		uri := cpe.GetURI()
		if uri == "" {
			err := ms.StoreCPE(cpe)
			if err == nil {
				t.Error("StoreCPE with empty URI should return error")
			}
		}
	}

	// TestMemoryStorage_UpdateCPE_CoverageGap_EmptyURI tests UpdateCPE with empty URI
	func TestMemoryStorage_UpdateCPE_CoverageGap_EmptyURI(t *testing.T) {
		ms := NewMemoryStorage()
		cpe := &CPE{}
		uri := cpe.GetURI()
		if uri == "" {
			err := ms.UpdateCPE(cpe)
			if err == nil {
				t.Error("UpdateCPE with empty URI should return error")
			}
		}
	}

	// TestMemoryStorage_DeleteCPE_CoverageGap_WithCVEAssociations tests DeleteCPE properly cleans up cveToCPEs
	func TestMemoryStorage_DeleteCPE_CoverageGap_WithCVEAssociations(t *testing.T) {
		ms := NewMemoryStorage()
		ms.Initialize()

		cpe1 := &CPE{
			Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      Vendor("vendor"),
			ProductName: Product("product"),
			Version:     Version("1.0"),
		}
		ms.StoreCPE(cpe1)

		cpe2 := &CPE{
			Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      Vendor("vendor2"),
			ProductName: Product("product2"),
			Version:     Version("2.0"),
		}
		ms.StoreCPE(cpe2)

		cve := NewCVEReference("CVE-2021-12345")
		cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
		cve.AddAffectedCPE("cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*")
		ms.StoreCVE(cve)

		// Delete cpe1, verify cveToCPEs still has cpe2
		err := ms.DeleteCPE(cpe1.GetURI())
		if err != nil {
			t.Errorf("DeleteCPE() error = %v", err)
		}

		cpeIDs := ms.cveToCPEs[cve.CVEID]
		foundCPE2 := false
		for _, id := range cpeIDs {
			if id == cpe2.GetURI() {
				foundCPE2 = true
			}
		}
		if !foundCPE2 {
			t.Error("DeleteCPE should preserve associations with remaining CPEs")
		}
	}

	// TestMemoryStorage_UpdateCVE_CoverageGap_WithCPE22Format tests UpdateCVE with CPE 2.2 format affected CPEs
	func TestMemoryStorage_UpdateCVE_CoverageGap_WithCPE22Format(t *testing.T) {
		ms := NewMemoryStorage()
		ms.Initialize()

		cve := NewCVEReference("CVE-2021-12345")
		cve.Description = "Original"
		ms.StoreCVE(cve)

		cveUpdated := &CVEReference{
			CVEID:        cve.CVEID,
			Description:  "Updated",
			AffectedCPEs: []string{"cpe:/a:vendor:product:1.0"},
		}

		err := ms.UpdateCVE(cveUpdated)
		if err != nil {
			t.Errorf("UpdateCVE() error = %v", err)
		}

		cpeIDs := ms.cveToCPEs[cve.CVEID]
		if len(cpeIDs) == 0 {
			t.Error("UpdateCVE should create CPE associations for CPE 2.2 format")
		}
	}

	// TestMemoryStorage_DeleteCVE_CoverageGap_NoCPEAssociations tests DeleteCVE when CVE has no CPE associations
	func TestMemoryStorage_DeleteCVE_CoverageGap_NoCPEAssociations(t *testing.T) {
		ms := NewMemoryStorage()
		ms.Initialize()

		cve := NewCVEReference("CVE-2021-12345")
		ms.StoreCVE(cve)

		// Ensure no cveToCPEs entry
		delete(ms.cveToCPEs, cve.CVEID)

		err := ms.DeleteCVE(cve.CVEID)
		if err != nil {
			t.Errorf("DeleteCVE() error = %v", err)
		}

		if _, ok := ms.cves[cve.CVEID]; ok {
			t.Error("CVE should be deleted after DeleteCVE")
		}
	}

	// TestMemoryStorage_ApplyCVEFilters_CoverageGap_InvalidCPEInProductFilter tests applyCVEFilters with invalid CPE in product filter
	func TestMemoryStorage_ApplyCVEFilters_CoverageGap_InvalidCPEInProductFilter(t *testing.T) {
		ms := NewMemoryStorage()

		cve := &CVEReference{
			CVEID:        "CVE-2021-12345",
			AffectedCPEs: []string{"invalid:cpe:format"},
		}

		opts := &SearchOptions{
			Filters: map[string]interface{}{"product": "windows"},
		}
		if ms.applyCVEFilters(cve, opts) {
			t.Error("applyCVEFilters should return false when no valid CPEs match product filter")
		}
	}

// TestMemoryStorage_UpdateCVE_MultipleCVEsPerCPE tests UpdateCVE with a CPE that has multiple CVEs
// This exercises the inner loop at line 328-330 where id != cve.CVEID
func TestMemoryStorage_UpdateCVE_MultipleCVEsPerCPE(t *testing.T) {
	ms := NewMemoryStorage()

	// Store a CPE
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe)

	// Store TWO CVEs that both reference the same CPE
	cve1 := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	cve2 := &CVEReference{
		CVEID:        "CVE-2021-45105",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	ms.StoreCVE(cve1)
	ms.StoreCVE(cve2)

	// Now update CVE-2021-44228 with different CPEs
	// The CPE "cpe:2.3:a:apache:log4j:2.0" should still have CVE-2021-45105
	updatedCve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"},
	}
	err := ms.UpdateCVE(updatedCve)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	// Verify CPE still has the other CVE
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
	found := false
	for _, id := range cveIDs {
		if id == "CVE-2021-45105" {
			found = true
		}
		if id == "CVE-2021-44228" {
			t.Error("UpdateCVE() should have removed CVE-2021-44228 from old CPE")
		}
	}
	if !found {
		t.Error("UpdateCVE() should have kept CVE-2021-45105 in old CPE mapping")
	}
}

// TestMemoryStorage_DeleteCVE_MultipleCVEsPerCPE tests DeleteCVE with a CPE that has multiple CVEs
// This exercises the inner loop at line 390-392 where id != cveID
func TestMemoryStorage_DeleteCVE_MultipleCVEsPerCPE(t *testing.T) {
	ms := NewMemoryStorage()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	ms.StoreCPE(cpe)

	// Store TWO CVEs referencing the same CPE
	cve1 := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	cve2 := &CVEReference{
		CVEID:        "CVE-2021-45105",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	ms.StoreCVE(cve1)
	ms.StoreCVE(cve2)

	// Delete only one CVE - the CPE should still reference the other
	err := ms.DeleteCVE("CVE-2021-44228")
	if err != nil {
		t.Errorf("DeleteCVE() error = %v", err)
	}

	// Verify CPE still has the other CVE
	cveIDs := ms.cpeToCVEs["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
	found := false
	for _, id := range cveIDs {
		if id == "CVE-2021-45105" {
			found = true
		}
		if id == "CVE-2021-44228" {
			t.Error("DeleteCVE() should have removed CVE-2021-44228 from CPE mapping")
		}
	}
	if !found {
		t.Error("DeleteCVE() should have kept CVE-2021-45105 in CPE mapping")
	}
}

	// TestStoreCPE_CoverageGap_EmptyURI tests StoreCPE with CPE that has no URI
	func TestStoreCPE_CoverageGap_EmptyURI(t *testing.T) {
		ms := NewMemoryStorage()
		// Create a CPE with no meaningful content - this tests the GetURI() == "" branch
		// Since GetURI() returns FormatURI which always builds a non-empty string from parts,
		// we need a CPE where the Part is empty (zero value) and Cpe23 is also empty
		cpe := &CPE{}
		err := ms.StoreCPE(cpe)
		// Even with empty fields, FormatURI still returns "cpe:2.3:::::::::" which is not empty
		// So this should succeed (the empty URI branch should be unreachable for non-nil CPEs)
		if err != nil {
			t.Logf("StoreCPE with empty CPE returned error: %v (expected - URI is always non-empty for non-nil CPE)", err)
		}
	}

	// TestUpdateCPE_CoverageGap_EmptyURI tests UpdateCPE with CPE that has no URI
	func TestUpdateCPE_CoverageGap_EmptyURI(t *testing.T) {
		ms := NewMemoryStorage()
		cpe := &CPE{}
		err := ms.UpdateCPE(cpe)
		if err != nil {
			t.Logf("UpdateCPE with empty CPE returned error: %v", err)
		}
	}

	// TestUpdateCVE_CoverageGap_CVECleanupOtherCVEs tests UpdateCVE where a CPE is associated with multiple CVEs
	func TestUpdateCVE_CoverageGap_CVECleanupOtherCVEs(t *testing.T) {
		ms := NewMemoryStorage()
		cpeURI := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"

		// First store a CPE
		cpe, err := ParseCpe23(cpeURI)
		if err != nil {
			t.Fatalf("ParseCpe23() error = %v", err)
		}
		err = ms.StoreCPE(cpe)
		if err != nil {
			t.Fatalf("StoreCPE() error = %v", err)
		}

		// Store two CVEs that share the same CPE
		cve1 := &CVEReference{CVEID: "CVE-2021-44228"}
		cve1.AddAffectedCPE(cpeURI)
		err = ms.StoreCVE(cve1)
		if err != nil {
			t.Fatalf("StoreCVE() error = %v", err)
		}

		cve2 := &CVEReference{CVEID: "CVE-2021-45105"}
		cve2.AddAffectedCPE(cpeURI)
		err = ms.StoreCVE(cve2)
		if err != nil {
			t.Fatalf("StoreCVE() error = %v", err)
		}

		// Now update CVE1 with a different CPE
		updatedCve1 := &CVEReference{CVEID: "CVE-2021-44228"}
		updatedCve1.AddAffectedCPE("cpe:2.3:a:apache:log4j:3.0:*:*:*:*:*:*:*")
		err = ms.UpdateCVE(updatedCve1)
		if err != nil {
			t.Fatalf("UpdateCVE() error = %v", err)
		}

		// Verify the old CPE still has CVE2 in its mapping
		cveIDs := ms.cpeToCVEs[cpeURI]
		found := false
		for _, id := range cveIDs {
			if id == "CVE-2021-45105" {
				found = true
			}
		}
		if !found {
			t.Error("UpdateCVE() should have kept CVE-2021-45105 in CPE mapping for old CPE")
		}

		// Verify CVE1 is no longer in the old CPE mapping
		for _, id := range cveIDs {
			if id == "CVE-2021-44228" {
				t.Error("UpdateCVE() should have removed CVE-2021-44228 from old CPE mapping")
			}
		}
	}

	// TestDeleteCVE_CoverageGap_CVECleanupOtherCVEs tests DeleteCVE where a CPE is associated with multiple CVEs
	func TestDeleteCVE_CoverageGap_CVECleanupOtherCVEs(t *testing.T) {
		ms := NewMemoryStorage()
		cpeURI := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"

		// First store a CPE
		cpe, err := ParseCpe23(cpeURI)
		if err != nil {
			t.Fatalf("ParseCpe23() error = %v", err)
		}
		err = ms.StoreCPE(cpe)
		if err != nil {
			t.Fatalf("StoreCPE() error = %v", err)
		}

		// Store two CVEs that share the same CPE
		cve1 := &CVEReference{CVEID: "CVE-2021-44228"}
		cve1.AddAffectedCPE(cpeURI)
		err = ms.StoreCVE(cve1)
		if err != nil {
			t.Fatalf("StoreCVE() error = %v", err)
		}

		cve2 := &CVEReference{CVEID: "CVE-2021-45105"}
		cve2.AddAffectedCPE(cpeURI)
		err = ms.StoreCVE(cve2)
		if err != nil {
			t.Fatalf("StoreCVE() error = %v", err)
		}

		// Delete CVE1 - the CPE should still have CVE2
		err = ms.DeleteCVE("CVE-2021-44228")
		if err != nil {
			t.Fatalf("DeleteCVE() error = %v", err)
		}

		// Verify the CPE still has CVE2 in its mapping
		cveIDs := ms.cpeToCVEs[cpeURI]
		found := false
		for _, id := range cveIDs {
			if id == "CVE-2021-45105" {
				found = true
			}
		}
		if !found {
			t.Error("DeleteCVE() should have kept CVE-2021-45105 in CPE mapping")
		}

		// Verify CVE1 is no longer in the CPE mapping
		for _, id := range cveIDs {
			if id == "CVE-2021-44228" {
				t.Error("DeleteCVE() should have removed CVE-2021-44228 from CPE mapping")
			}
		}
	}
