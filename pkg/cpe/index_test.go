package cpeskills

import (
	"testing"
)

func TestNewCPEIndex(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14.1"},
		{Part: *PartApplication, Vendor: "apache", ProductName: "httpd", Version: "2.4.0"},
		{Part: *PartApplication, Vendor: "microsoft", ProductName: "office", Version: "2019"},
		{Part: *PartOperationSystem, Vendor: "microsoft", ProductName: "windows", Version: "10"},
		nil,
	}

	idx := NewCPEIndex(cpes)
	if idx.Size() != 4 {
		t.Errorf("expected 4 CPEs, got %d", idx.Size())
	}
	if idx.VendorCount() != 2 {
		t.Errorf("expected 2 vendors, got %d", idx.VendorCount())
	}
	if idx.ProductCount() != 4 {
		t.Errorf("expected 4 products, got %d", idx.ProductCount())
	}
}

func TestCPEIndex_Lookup(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14.1"},
		{Part: *PartApplication, Vendor: "apache", ProductName: "httpd", Version: "2.4.0"},
		{Part: *PartApplication, Vendor: "microsoft", ProductName: "office", Version: "2019"},
	}
	idx := NewCPEIndex(cpes)

	// 按 vendor 查找
	results := idx.Lookup(&CPE{Vendor: "apache"})
	if len(results) != 2 {
		t.Errorf("expected 2 results for vendor 'apache', got %d", len(results))
	}

	// 按 vendor + product 查找
	results = idx.Lookup(&CPE{Vendor: "apache", ProductName: "log4j"})
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	// 按 product 查找
	results = idx.Lookup(&CPE{ProductName: "office"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for product 'office', got %d", len(results))
	}

	// 按 part 查找
	results = idx.Lookup(&CPE{Part: *PartApplication})
	if len(results) != 3 {
		t.Errorf("expected 3 application CPEs, got %d", len(results))
	}

	// nil criteria → all
	results = idx.Lookup(nil)
	if len(results) != 3 {
		t.Errorf("expected all 3 CPEs, got %d", len(results))
	}

	// 不存在的 vendor
	results = idx.Lookup(&CPE{Vendor: "nonexistent"})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestCPEIndex_IndexPURL(t *testing.T) {
	idx := NewCPEIndex(nil)
	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	purl := NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")

	idx.IndexPURL(purl, cpe)

	found := idx.LookupByPURL(purl)
	if found == nil {
		t.Error("expected to find CPE by PURL")
	}

	// nil PURL
	if idx.LookupByPURL(nil) != nil {
		t.Error("expected nil for nil PURL")
	}
}

func TestCPEIndex_GetByVendor(t *testing.T) {
	cpes := []*CPE{
		{Vendor: "apache", ProductName: "log4j"},
		{Vendor: "microsoft", ProductName: "office"},
	}
	idx := NewCPEIndex(cpes)

	apache := idx.GetByVendor("apache")
	if len(apache) != 1 {
		t.Errorf("expected 1 apache CPE, got %d", len(apache))
	}

	none := idx.GetByVendor("nonexistent")
	if len(none) != 0 {
		t.Errorf("expected 0, got %d", len(none))
	}
}

func TestCPEIndex_GetByProduct(t *testing.T) {
	cpes := []*CPE{
		{Vendor: "apache", ProductName: "log4j"},
		{Vendor: "apache", ProductName: "httpd"},
	}
	idx := NewCPEIndex(cpes)

	log4j := idx.GetByProduct("log4j")
	if len(log4j) != 1 {
		t.Errorf("expected 1 log4j CPE, got %d", len(log4j))
	}
}

func TestCPEIndex_GetByPart(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j"},
		{Part: *PartOperationSystem, Vendor: "microsoft", ProductName: "windows"},
	}
	idx := NewCPEIndex(cpes)

	apps := idx.GetByPart("a")
	if len(apps) != 1 {
		t.Errorf("expected 1 application CPE, got %d", len(apps))
	}
}

func TestCPEIndex_All(t *testing.T) {
	cpes := []*CPE{
		{Vendor: "apache", ProductName: "log4j"},
		{Vendor: "microsoft", ProductName: "office"},
	}
	idx := NewCPEIndex(cpes)
	all := idx.All()
	if len(all) != 2 {
		t.Errorf("expected 2 CPEs, got %d", len(all))
	}
}

func TestCPEIndex_Add(t *testing.T) {
	idx := NewCPEIndex(nil)

	if idx.Size() != 0 {
		t.Errorf("expected initial size 0, got %d", idx.Size())
	}

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	idx.Add(cpe)

	if idx.Size() != 1 {
		t.Errorf("expected size 1 after Add, got %d", idx.Size())
	}

	// Verify it can be looked up
	results := idx.Lookup(&CPE{Vendor: "apache"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for vendor 'apache' after Add, got %d", len(results))
	}

	// Verify product lookup
	results = idx.Lookup(&CPE{ProductName: "log4j"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for product 'log4j' after Add, got %d", len(results))
	}

	// Verify part lookup
	results = idx.Lookup(&CPE{Part: *PartApplication})
	if len(results) != 1 {
		t.Errorf("expected 1 result for part 'a' after Add, got %d", len(results))
	}
}

func TestCPEIndex_Add_Nil(t *testing.T) {
	idx := NewCPEIndex(nil)
	idx.Add(nil)

	if idx.Size() != 0 {
		t.Errorf("expected size 0 after Add(nil), got %d", idx.Size())
	}
}

func TestCPEIndex_Add_Multiple(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe1, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	cpe2, _ := Parse("cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*")
	cpe3, _ := Parse("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")

	idx.Add(cpe1)
	idx.Add(cpe2)
	idx.Add(cpe3)

	if idx.Size() != 3 {
		t.Errorf("expected size 3 after 3 Adds, got %d", idx.Size())
	}

	// Verify vendor index
	apache := idx.GetByVendor("apache")
	if len(apache) != 2 {
		t.Errorf("expected 2 apache CPEs, got %d", len(apache))
	}
	microsoft := idx.GetByVendor("microsoft")
	if len(microsoft) != 1 {
		t.Errorf("expected 1 microsoft CPE, got %d", len(microsoft))
	}
}

func TestCPEIndex_Add_Then_Lookup(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	idx.Add(cpe)

	// Lookup by vendor+product
	results := idx.Lookup(&CPE{Vendor: "apache", ProductName: "log4j"})
	if len(results) != 1 {
		t.Errorf("expected 1 result for vendor+product lookup, got %d", len(results))
	}
	if results[0].Version != "2.14.1" {
		t.Errorf("expected version 2.14.1, got %s", results[0].Version)
	}
}

func TestCPEIndex_Remove(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	idx.Add(cpe)

	if idx.Size() != 1 {
		t.Fatalf("expected size 1 before Remove, got %d", idx.Size())
	}

	idx.Remove(cpe.Cpe23)

	if idx.Size() != 0 {
		t.Errorf("expected size 0 after Remove, got %d", idx.Size())
	}

	// Verify it's gone from vendor index
	results := idx.Lookup(&CPE{Vendor: "apache"})
	if len(results) != 0 {
		t.Errorf("expected 0 results for vendor 'apache' after Remove, got %d", len(results))
	}
}

func TestCPEIndex_Remove_NonExisting(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	idx.Add(cpe)

	// Remove a non-existing URI should be no-op
	idx.Remove("cpe:2.3:a:nonexistent:foo:1.0:*:*:*:*:*:*:*")

	if idx.Size() != 1 {
		t.Errorf("expected size 1 after removing non-existing CPE, got %d", idx.Size())
	}
}

func TestCPEIndex_Remove_FromMultiple(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe1, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	cpe2, _ := Parse("cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*")
	idx.Add(cpe1)
	idx.Add(cpe2)

	if idx.Size() != 2 {
		t.Fatalf("expected size 2 before Remove, got %d", idx.Size())
	}

	// Remove one of the two apache CPEs
	idx.Remove(cpe1.Cpe23)

	if idx.Size() != 1 {
		t.Errorf("expected size 1 after Remove, got %d", idx.Size())
	}

	// The other apache CPE should still be there
	apache := idx.GetByVendor("apache")
	if len(apache) != 1 {
		t.Errorf("expected 1 apache CPE after Remove, got %d", len(apache))
	}
}

func TestCPEIndex_Clear(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe1, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	cpe2, _ := Parse("cpe:2.3:a:apache:httpd:2.4.0:*:*:*:*:*:*:*")
	idx.Add(cpe1)
	idx.Add(cpe2)

	if idx.Size() != 2 {
		t.Fatalf("expected size 2 before Clear, got %d", idx.Size())
	}

	idx.Clear()

	if idx.Size() != 0 {
		t.Errorf("expected size 0 after Clear, got %d", idx.Size())
	}

	// Verify all indexes are empty
	if idx.VendorCount() != 0 {
		t.Errorf("expected 0 vendors after Clear, got %d", idx.VendorCount())
	}
	if idx.ProductCount() != 0 {
		t.Errorf("expected 0 products after Clear, got %d", idx.ProductCount())
	}
}

func TestCPEIndex_Add_Then_Clear_Then_Size(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	idx.Add(cpe)

	if idx.Size() != 1 {
		t.Fatalf("expected size 1 after Add, got %d", idx.Size())
	}

	idx.Clear()

	if idx.Size() != 0 {
		t.Errorf("expected size 0 after Clear, got %d", idx.Size())
	}

	// Can add again after Clear
	cpe2, _ := Parse("cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*")
	idx.Add(cpe2)

	if idx.Size() != 1 {
		t.Errorf("expected size 1 after Add post-Clear, got %d", idx.Size())
	}
}

func TestCPEIndex_Remove_AlsoRemovesFromPURLIndex(t *testing.T) {
	idx := NewCPEIndex(nil)

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	purl := NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1")
	idx.Add(cpe)
	idx.IndexPURL(purl, cpe)

	// Verify PURL lookup works
	if idx.LookupByPURL(purl) == nil {
		t.Fatal("expected to find CPE by PURL before Remove")
	}

	idx.Remove(cpe.Cpe23)

	// PURL mapping should also be removed
	if idx.LookupByPURL(purl) != nil {
		t.Error("expected nil PURL lookup after Remove")
	}
}
