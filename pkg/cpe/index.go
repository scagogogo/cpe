package cpeskills

import (
	"sync"
)

// CPEIndex provides fast in-memory indexing for CPE lookups with O(1) complexity.
//
// Supports concurrent reads and writes through a read-write mutex.
// Thread-safe for use in concurrent batch scanning scenarios.
type CPEIndex struct {
	// mu protects all map fields
	mu sync.RWMutex

	// byVendor index by vendor name
	byVendor map[string][]*CPE

	// byProduct index by product name
	byProduct map[string][]*CPE

	// byPart index by part (a/h/o)
	byPart map[string][]*CPE

	// byPURL index by PURL string
	byPURL map[string]*CPE

	// all all CPEs in the index
	all []*CPE
}

// NewCPEIndex creates a new CPE index from a CPE slice.
func NewCPEIndex(cpes []*CPE) *CPEIndex {
	idx := &CPEIndex{
		byVendor:  make(map[string][]*CPE),
		byProduct: make(map[string][]*CPE),
		byPart:    make(map[string][]*CPE),
		byPURL:    make(map[string]*CPE),
		all:       make([]*CPE, 0, len(cpes)),
	}

	for _, c := range cpes {
		if c == nil {
			continue
		}
		idx.all = append(idx.all, c)

		// Index by vendor
		vendor := string(c.Vendor)
		if vendor != "" && vendor != ValueANY {
			idx.byVendor[vendor] = append(idx.byVendor[vendor], c)
		}

		// Index by product
		product := string(c.ProductName)
		if product != "" && product != ValueANY {
			idx.byProduct[product] = append(idx.byProduct[product], c)
		}

		// Index by part
		part := string(c.Part.ShortName)
		if part != "" {
			idx.byPart[part] = append(idx.byPart[part], c)
		}
	}

	return idx
}

// Lookup finds CPEs matching the given criteria (O(1) average).
//
// Thread-safe for concurrent reads.
func (idx *CPEIndex) Lookup(criteria *CPE) []*CPE {
	if criteria == nil {
		idx.mu.RLock()
		defer idx.mu.RUnlock()
		result := make([]*CPE, len(idx.all))
		copy(result, idx.all)
		return result
	}

	// Prefer vendor index
	vendor := string(criteria.Vendor)
	if vendor != "" && vendor != ValueANY {
		idx.mu.RLock()
		cpes, ok := idx.byVendor[vendor]
		if ok {
			// Further filter by product
			product := string(criteria.ProductName)
			if product != "" && product != ValueANY {
				var filtered []*CPE
				for _, c := range cpes {
					if string(c.ProductName) == product {
						filtered = append(filtered, c)
					}
				}
				idx.mu.RUnlock()
				return filtered
			}
			idx.mu.RUnlock()
			return cpes
		}
		idx.mu.RUnlock()
		return nil
	}

	// Use product index
	product := string(criteria.ProductName)
	if product != "" && product != ValueANY {
		idx.mu.RLock()
		cpes, ok := idx.byProduct[product]
		idx.mu.RUnlock()
		if ok {
			return cpes
		}
		return nil
	}

	// Use part index
	part := string(criteria.Part.ShortName)
	if part != "" {
		idx.mu.RLock()
		cpes, ok := idx.byPart[part]
		idx.mu.RUnlock()
		if ok {
			return cpes
		}
		return nil
	}

	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*CPE, len(idx.all))
	copy(result, idx.all)
	return result
}

// LookupByPURL finds a CPE by its PURL mapping.
//
// Thread-safe for concurrent reads.
func (idx *CPEIndex) LookupByPURL(purl *PackageURL) *CPE {
	if purl == nil {
		return nil
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byPURL[purl.String()]
}

// IndexPURL maps a PURL to a CPE.
//
// Thread-safe for concurrent writes.
func (idx *CPEIndex) IndexPURL(purl *PackageURL, cpe *CPE) {
	if purl == nil || cpe == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.byPURL[purl.String()] = cpe
}

// Size returns the number of CPEs in the index.
func (idx *CPEIndex) Size() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.all)
}

// All returns a copy of all CPEs in the index.
func (idx *CPEIndex) All() []*CPE {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	result := make([]*CPE, len(idx.all))
	copy(result, idx.all)
	return result
}

// GetByVendor returns all CPEs for a given vendor.
func (idx *CPEIndex) GetByVendor(vendor string) []*CPE {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byVendor[vendor]
}

// GetByProduct returns all CPEs for a given product.
func (idx *CPEIndex) GetByProduct(product string) []*CPE {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byProduct[product]
}

// GetByPart returns all CPEs for a given part.
func (idx *CPEIndex) GetByPart(part string) []*CPE {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return idx.byPart[part]
}

// VendorCount returns the number of distinct vendors.
func (idx *CPEIndex) VendorCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.byVendor)
}

// ProductCount returns the number of distinct products.
func (idx *CPEIndex) ProductCount() int {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	return len(idx.byProduct)
}

// Add adds a CPE to the index.
//
// Thread-safe for concurrent writes.
func (idx *CPEIndex) Add(cpe *CPE) {
	if cpe == nil {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.all = append(idx.all, cpe)

	vendor := string(cpe.Vendor)
	if vendor != "" && vendor != ValueANY {
		idx.byVendor[vendor] = append(idx.byVendor[vendor], cpe)
	}

	product := string(cpe.ProductName)
	if product != "" && product != ValueANY {
		idx.byProduct[product] = append(idx.byProduct[product], cpe)
	}

	part := string(cpe.Part.ShortName)
	if part != "" {
		idx.byPart[part] = append(idx.byPart[part], cpe)
	}
}

// Remove removes a CPE from the index by its URI.
//
// Thread-safe for concurrent writes.
func (idx *CPEIndex) Remove(cpeURI string) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Find and remove from all
	for i, c := range idx.all {
		if c.Cpe23 == cpeURI {
			idx.all = append(idx.all[:i], idx.all[i+1:]...)
			break
		}
	}

	// Remove from vendor index
	for vendor, cpes := range idx.byVendor {
		for i, c := range cpes {
			if c.Cpe23 == cpeURI {
				idx.byVendor[vendor] = append(cpes[:i], cpes[i+1:]...)
				break
			}
		}
	}

	// Remove from product index
	for product, cpes := range idx.byProduct {
		for i, c := range cpes {
			if c.Cpe23 == cpeURI {
				idx.byProduct[product] = append(cpes[:i], cpes[i+1:]...)
				break
			}
		}
	}

	// Remove from PURL index
	for purl, c := range idx.byPURL {
		if c.Cpe23 == cpeURI {
			delete(idx.byPURL, purl)
			break
		}
	}
}

// Clear removes all entries from the index.
func (idx *CPEIndex) Clear() {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.byVendor = make(map[string][]*CPE)
	idx.byProduct = make(map[string][]*CPE)
	idx.byPart = make(map[string][]*CPE)
	idx.byPURL = make(map[string]*CPE)
	idx.all = nil
}
