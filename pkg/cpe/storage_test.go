package cpeskills

import (
	"errors"
	"testing"
	"time"
)

// mockStorage is a mock implementation of the Storage interface for testing
type mockStorage struct {
	cpes             map[string]*CPE
	cves             map[string]*CVEReference
	dictionary       *CPEDictionary
	timestamps       map[string]time.Time
	storeCPEErr      error
	retrieveCPEErr   error
	storeCVEErr      error
	retrieveCVEErr   error
	searchCPEErr     error
	searchCVEErr     error
	initErr          error
	closeErr         error
	deleteCPEErr     error
	retrieveDictErr  error
	retrieveTSErr    error
	updateCVEErr     error
	deleteCVEErr     error
	updateCPEErr     error
	advSearchCPEErr  error
	findCVEsByCPEErr error
	findCPEsByCVEErr error
	storeDictErr     error
	storeTSErr       error
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		cpes:       make(map[string]*CPE),
		cves:       make(map[string]*CVEReference),
		timestamps: make(map[string]time.Time),
	}
}

func (m *mockStorage) Initialize() error {
	return m.initErr
}

func (m *mockStorage) Close() error {
	return m.closeErr
}

func (m *mockStorage) StoreCPE(cpe *CPE) error {
	if m.storeCPEErr != nil {
		return m.storeCPEErr
	}
	m.cpes[cpe.GetURI()] = cpe
	return nil
}

func (m *mockStorage) RetrieveCPE(id string) (*CPE, error) {
	if m.retrieveCPEErr != nil {
		return nil, m.retrieveCPEErr
	}
	cpe, ok := m.cpes[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cpe, nil
}

func (m *mockStorage) UpdateCPE(cpe *CPE) error {
	if m.updateCPEErr != nil {
		return m.updateCPEErr
	}
	m.cpes[cpe.GetURI()] = cpe
	return nil
}

func (m *mockStorage) DeleteCPE(id string) error {
	if m.deleteCPEErr != nil {
		return m.deleteCPEErr
	}
	delete(m.cpes, id)
	return nil
}

func (m *mockStorage) SearchCPE(criteria *CPE, options *MatchOptions) ([]*CPE, error) {
	if m.searchCPEErr != nil {
		return nil, m.searchCPEErr
	}
	var results []*CPE
	for _, cpe := range m.cpes {
		results = append(results, cpe)
	}
	return results, nil
}

func (m *mockStorage) AdvancedSearchCPE(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error) {
	if m.advSearchCPEErr != nil {
		return nil, m.advSearchCPEErr
	}
	var results []*CPE
	for _, cpe := range m.cpes {
		results = append(results, cpe)
	}
	return results, nil
}

func (m *mockStorage) StoreCVE(cve *CVEReference) error {
	if m.storeCVEErr != nil {
		return m.storeCVEErr
	}
	m.cves[cve.CVEID] = cve
	return nil
}

func (m *mockStorage) RetrieveCVE(cveID string) (*CVEReference, error) {
	if m.retrieveCVEErr != nil {
		return nil, m.retrieveCVEErr
	}
	cve, ok := m.cves[cveID]
	if !ok {
		return nil, ErrNotFound
	}
	return cve, nil
}

func (m *mockStorage) UpdateCVE(cve *CVEReference) error {
	if m.updateCVEErr != nil {
		return m.updateCVEErr
	}
	m.cves[cve.CVEID] = cve
	return nil
}

func (m *mockStorage) DeleteCVE(cveID string) error {
	if m.deleteCVEErr != nil {
		return m.deleteCVEErr
	}
	delete(m.cves, cveID)
	return nil
}

func (m *mockStorage) SearchCVE(query string, options *SearchOptions) ([]*CVEReference, error) {
	if m.searchCVEErr != nil {
		return nil, m.searchCVEErr
	}
	var results []*CVEReference
	for _, cve := range m.cves {
		results = append(results, cve)
	}
	return results, nil
}

func (m *mockStorage) FindCVEsByCPE(cpe *CPE) ([]*CVEReference, error) {
	if m.findCVEsByCPEErr != nil {
		return nil, m.findCVEsByCPEErr
	}
	var results []*CVEReference
	for _, cve := range m.cves {
		results = append(results, cve)
	}
	return results, nil
}

func (m *mockStorage) FindCPEsByCVE(cveID string) ([]*CPE, error) {
	if m.findCPEsByCVEErr != nil {
		return nil, m.findCPEsByCVEErr
	}
	var results []*CPE
	for _, cpe := range m.cpes {
		results = append(results, cpe)
	}
	return results, nil
}

func (m *mockStorage) StoreDictionary(dict *CPEDictionary) error {
	if m.storeDictErr != nil {
		return m.storeDictErr
	}
	m.dictionary = dict
	return nil
}

func (m *mockStorage) RetrieveDictionary() (*CPEDictionary, error) {
	if m.retrieveDictErr != nil {
		return nil, m.retrieveDictErr
	}
	if m.dictionary == nil {
		return nil, ErrNotFound
	}
	return m.dictionary, nil
}

func (m *mockStorage) StoreModificationTimestamp(key string, timestamp time.Time) error {
	if m.storeTSErr != nil {
		return m.storeTSErr
	}
	m.timestamps[key] = timestamp
	return nil
}

func (m *mockStorage) RetrieveModificationTimestamp(key string) (time.Time, error) {
	if m.retrieveTSErr != nil {
		return time.Time{}, m.retrieveTSErr
	}
	ts, ok := m.timestamps[key]
	if !ok {
		return time.Time{}, ErrNotFound
	}
	return ts, nil
}

// --- Tests for NewSearchOptions ---

func TestStorage_NewSearchOptions(t *testing.T) {
	opts := NewSearchOptions()

	if opts.Offset != 0 {
		t.Errorf("Offset = %d, want 0", opts.Offset)
	}
	if opts.Limit != 100 {
		t.Errorf("Limit = %d, want 100", opts.Limit)
	}
	if opts.SortBy != "id" {
		t.Errorf("SortBy = %s, want id", opts.SortBy)
	}
	if opts.SortAscending != true {
		t.Errorf("SortAscending = %v, want true", opts.SortAscending)
	}
	if opts.Filters == nil {
		t.Errorf("Filters is nil, want non-nil map")
	}
	if len(opts.Filters) != 0 {
		t.Errorf("Filters has %d items, want 0", len(opts.Filters))
	}
	if opts.IncludeDeprecated != false {
		t.Errorf("IncludeDeprecated = %v, want false", opts.IncludeDeprecated)
	}
}

// --- Tests for NewStorageManager ---

func TestStorage_NewStorageManager(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	if sm.Primary != mock {
		t.Errorf("Primary not set correctly")
	}
	if sm.Cache != nil {
		t.Errorf("Cache should be nil by default")
	}
	if sm.CacheEnabled != false {
		t.Errorf("CacheEnabled should be false by default")
	}
	if sm.CacheTTLSeconds != 3600 {
		t.Errorf("CacheTTLSeconds = %d, want 3600", sm.CacheTTLSeconds)
	}
}

// --- Tests for SetCache ---

func TestStorage_SetCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	cache := newMockStorage()
	sm.SetCache(cache)

	if sm.Cache != cache {
		t.Errorf("Cache not set correctly")
	}
	if sm.CacheEnabled != true {
		t.Errorf("CacheEnabled should be true after SetCache")
	}
}

// --- Tests for GetCPE ---

func TestStorage_GetCPE_FromCache(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	// Store CPE only in cache
	cache.cpes[testCPE.GetURI()] = testCPE

	result, err := sm.GetCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("GetCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("GetCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}
}

func TestStorage_GetCPE_CacheMiss_PrimaryHit(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	// Store CPE only in primary
	mock.cpes[testCPE.GetURI()] = testCPE

	result, err := sm.GetCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("GetCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("GetCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}

	// Verify it was populated into the cache
	if _, ok := cache.cpes[testCPE.GetURI()]; !ok {
		t.Errorf("GetCPE() should have populated cache")
	}
}

func TestStorage_GetCPE_NoCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	result, err := sm.GetCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("GetCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("GetCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}
}

func TestStorage_GetCPE_PrimaryError(t *testing.T) {
	mock := newMockStorage()
	mock.retrieveCPEErr = ErrNotFound
	sm := NewStorageManager(mock)

	_, err := sm.GetCPE("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCPE() error = %v, want ErrNotFound", err)
	}
}

func TestStorage_GetCPE_CacheEnabledButNilCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)
	sm.CacheEnabled = true
	sm.Cache = nil

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	result, err := sm.GetCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("GetCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("GetCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}
}

// --- Tests for StoreCPE ---

func TestStorage_StoreCPE(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	err := sm.StoreCPE(testCPE)
	if err != nil {
		t.Errorf("StoreCPE() error = %v", err)
	}
	if _, ok := mock.cpes[testCPE.GetURI()]; !ok {
		t.Errorf("StoreCPE() should store in primary")
	}
}

func TestStorage_StoreCPE_WithCache(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	err := sm.StoreCPE(testCPE)
	if err != nil {
		t.Errorf("StoreCPE() error = %v", err)
	}
	if _, ok := cache.cpes[testCPE.GetURI()]; !ok {
		t.Errorf("StoreCPE() should also store in cache")
	}
}

func TestStorage_StoreCPE_PrimaryError(t *testing.T) {
	mock := newMockStorage()
	mock.storeCPEErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	err := sm.StoreCPE(testCPE)
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("StoreCPE() error = %v, want ErrStorageDisconnected", err)
	}
}

// --- Tests for GetCVE ---

func TestStorage_GetCVE_FromCache(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCVE := NewCVEReference("CVE-2021-12345")
	cache.cves[testCVE.CVEID] = testCVE

	result, err := sm.GetCVE(testCVE.CVEID)
	if err != nil {
		t.Errorf("GetCVE() error = %v", err)
	}
	if result.CVEID != testCVE.CVEID {
		t.Errorf("GetCVE() = %v, want %v", result.CVEID, testCVE.CVEID)
	}
}

func TestStorage_GetCVE_CacheMiss_PrimaryHit(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCVE := NewCVEReference("CVE-2021-12345")
	mock.cves[testCVE.CVEID] = testCVE

	result, err := sm.GetCVE(testCVE.CVEID)
	if err != nil {
		t.Errorf("GetCVE() error = %v", err)
	}
	if result.CVEID != testCVE.CVEID {
		t.Errorf("GetCVE() = %v, want %v", result.CVEID, testCVE.CVEID)
	}

	// Verify populated into cache
	if _, ok := cache.cves[testCVE.CVEID]; !ok {
		t.Errorf("GetCVE() should have populated cache")
	}
}

func TestStorage_GetCVE_NoCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCVE := NewCVEReference("CVE-2021-12345")
	mock.cves[testCVE.CVEID] = testCVE

	result, err := sm.GetCVE(testCVE.CVEID)
	if err != nil {
		t.Errorf("GetCVE() error = %v", err)
	}
	if result.CVEID != testCVE.CVEID {
		t.Errorf("GetCVE() = %v, want %v", result.CVEID, testCVE.CVEID)
	}
}

func TestStorage_GetCVE_PrimaryError(t *testing.T) {
	mock := newMockStorage()
	mock.retrieveCVEErr = ErrNotFound
	sm := NewStorageManager(mock)

	_, err := sm.GetCVE("CVE-nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCVE() error = %v, want ErrNotFound", err)
	}
}

// --- Tests for Search ---

func TestStorage_Search(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	results, err := sm.Search(&CPE{Vendor: Vendor("vendor")}, &MatchOptions{})
	if err != nil {
		t.Errorf("Search() error = %v", err)
	}
	if len(results) == 0 {
		t.Errorf("Search() returned no results")
	}
}

func TestStorage_Search_Error(t *testing.T) {
	mock := newMockStorage()
	mock.searchCPEErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)

	_, err := sm.Search(nil, nil)
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("Search() error = %v, want ErrStorageDisconnected", err)
	}
}

// --- Tests for AdvancedSearch ---

func TestStorage_AdvancedSearch(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	results, err := sm.AdvancedSearch(&CPE{Vendor: Vendor("vendor")}, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearch() error = %v", err)
	}
	if len(results) == 0 {
		t.Errorf("AdvancedSearch() returned no results")
	}
}

func TestStorage_AdvancedSearch_Error(t *testing.T) {
	mock := newMockStorage()
	mock.advSearchCPEErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)

	_, err := sm.AdvancedSearch(nil, nil)
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("AdvancedSearch() error = %v, want ErrStorageDisconnected", err)
	}
}

// --- Tests for InvalidateCache ---

func TestStorage_InvalidateCache(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	cache.cpes[testCPE.GetURI()] = testCPE

	sm.InvalidateCache(testCPE.GetURI())

	if _, ok := cache.cpes[testCPE.GetURI()]; ok {
		t.Errorf("InvalidateCache() should remove from cache")
	}
}

func TestStorage_InvalidateCache_NoCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	// Should not panic
	sm.InvalidateCache("any-id")
}

func TestStorage_InvalidateCache_CacheEnabledButNilCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)
	sm.CacheEnabled = true
	sm.Cache = nil

	// Should not panic
	sm.InvalidateCache("any-id")
}

// --- Tests for ClearCache ---

func TestStorage_ClearCache(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	err := sm.ClearCache()
	if err != nil {
		t.Errorf("ClearCache() error = %v", err)
	}
}

func TestStorage_ClearCache_Error(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	cache.initErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	err := sm.ClearCache()
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("ClearCache() error = %v, want ErrStorageDisconnected", err)
	}
}

func TestStorage_ClearCache_NoCache(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	err := sm.ClearCache()
	if err != nil {
		t.Errorf("ClearCache() error = %v, want nil when no cache", err)
	}
}

func TestStorage_ClearCache_CacheEnabledButNil(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)
	sm.CacheEnabled = true
	sm.Cache = nil

	err := sm.ClearCache()
	if err != nil {
		t.Errorf("ClearCache() error = %v, want nil when cache is nil", err)
	}
}

// --- Tests for GetStats ---

func TestStorage_GetStats(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	testCVE := NewCVEReference("CVE-2021-12345")
	mock.cves[testCVE.CVEID] = testCVE

	testTime := time.Now()
	mock.timestamps["last_update"] = testTime

	stats, err := sm.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}
	if stats.TotalCPEs != 1 {
		t.Errorf("TotalCPEs = %d, want 1", stats.TotalCPEs)
	}
	if stats.TotalCVEs != 1 {
		t.Errorf("TotalCVEs = %d, want 1", stats.TotalCVEs)
	}
}

func TestStorage_GetStats_SearchCPEError(t *testing.T) {
	mock := newMockStorage()
	mock.searchCPEErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)

	_, err := sm.GetStats()
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("GetStats() error = %v, want ErrStorageDisconnected", err)
	}
}

func TestStorage_GetStats_SearchCVEError(t *testing.T) {
	mock := newMockStorage()
	mock.searchCVEErr = ErrStorageDisconnected
	sm := NewStorageManager(mock)

	_, err := sm.GetStats()
	if !errors.Is(err, ErrStorageDisconnected) {
		t.Errorf("GetStats() error = %v, want ErrStorageDisconnected", err)
	}
}

func TestStorage_GetStats_NoDictionary(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	stats, err := sm.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}
	if stats.TotalDictionaryItems != 0 {
		t.Errorf("TotalDictionaryItems = %d, want 0", stats.TotalDictionaryItems)
	}
}

func TestStorage_GetStats_WithDictionary(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	mock.dictionary = &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
	}

	stats, err := sm.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}
	if stats.TotalDictionaryItems != 1 {
		t.Errorf("TotalDictionaryItems = %d, want 1", stats.TotalDictionaryItems)
	}
}

func TestStorage_GetStats_NoLastUpdateTimestamp(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	stats, err := sm.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}
	if stats.LastUpdated.IsZero() {
		t.Errorf("LastUpdated should default to current time when timestamp not found")
	}
}

func TestStorage_GetStats_WithLastUpdateTimestamp(t *testing.T) {
	mock := newMockStorage()
	sm := NewStorageManager(mock)

	testTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mock.timestamps["last_update"] = testTime

	stats, err := sm.GetStats()
	if err != nil {
		t.Errorf("GetStats() error = %v", err)
	}
	if stats.LastUpdated.Unix() != testTime.Unix() {
		t.Errorf("LastUpdated = %v, want %v", stats.LastUpdated, testTime)
	}
}

// --- Test error constants ---

func TestStorage_ErrorConstants(t *testing.T) {
	if ErrNotFound == nil {
		t.Errorf("ErrNotFound should not be nil")
	}
	if ErrDuplicate == nil {
		t.Errorf("ErrDuplicate should not be nil")
	}
	if ErrInvalidData == nil {
		t.Errorf("ErrInvalidData should not be nil")
	}
	if ErrStorageDisconnected == nil {
		t.Errorf("ErrStorageDisconnected should not be nil")
	}

	if ErrNotFound.Error() != "record not found" {
		t.Errorf("ErrNotFound = %q, want %q", ErrNotFound.Error(), "record not found")
	}
	if ErrDuplicate.Error() != "duplicate record" {
		t.Errorf("ErrDuplicate = %q, want %q", ErrDuplicate.Error(), "duplicate record")
	}
	if ErrInvalidData.Error() != "invalid data" {
		t.Errorf("ErrInvalidData = %q, want %q", ErrInvalidData.Error(), "invalid data")
	}
	if ErrStorageDisconnected.Error() != "storage is disconnected" {
		t.Errorf("ErrStorageDisconnected = %q, want %q", ErrStorageDisconnected.Error(), "storage is disconnected")
	}
}

// --- Test StorageStats struct ---

func TestStorage_StorageStats(t *testing.T) {
	now := time.Now()
	stats := StorageStats{
		TotalCPEs:           10,
		TotalCVEs:           20,
		TotalDictionaryItems: 5,
		StorageBytes:        1024,
		LastUpdated:         now,
	}

	if stats.TotalCPEs != 10 {
		t.Errorf("TotalCPEs = %d, want 10", stats.TotalCPEs)
	}
	if stats.TotalCVEs != 20 {
		t.Errorf("TotalCVEs = %d, want 20", stats.TotalCVEs)
	}
	if stats.TotalDictionaryItems != 5 {
		t.Errorf("TotalDictionaryItems = %d, want 5", stats.TotalDictionaryItems)
	}
	if stats.StorageBytes != 1024 {
		t.Errorf("StorageBytes = %d, want 1024", stats.StorageBytes)
	}
	if stats.LastUpdated != now {
		t.Errorf("LastUpdated mismatch")
	}
}

// --- Test SearchOptions struct fields ---

func TestStorage_SearchOptions_AllFields(t *testing.T) {
	startTime := time.Now()
	endTime := startTime.Add(24 * time.Hour)

	opts := &SearchOptions{
		Offset:            10,
		Limit:             50,
		SortBy:            "severity",
		SortAscending:     false,
		Filters:           map[string]interface{}{"vendor": "microsoft"},
		FullTextQuery:     "windows",
		IncludeDeprecated: true,
		DateStart:         &startTime,
		DateEnd:           &endTime,
		MinCVSS:           5.0,
		MaxCVSS:           9.0,
	}

	if opts.Offset != 10 {
		t.Errorf("Offset = %d, want 10", opts.Offset)
	}
	if opts.Limit != 50 {
		t.Errorf("Limit = %d, want 50", opts.Limit)
	}
	if opts.SortBy != "severity" {
		t.Errorf("SortBy = %s, want severity", opts.SortBy)
	}
	if opts.SortAscending != false {
		t.Errorf("SortAscending = %v, want false", opts.SortAscending)
	}
	if opts.FullTextQuery != "windows" {
		t.Errorf("FullTextQuery = %s, want windows", opts.FullTextQuery)
	}
	if opts.IncludeDeprecated != true {
		t.Errorf("IncludeDeprecated = %v, want true", opts.IncludeDeprecated)
	}
	if opts.MinCVSS != 5.0 {
		t.Errorf("MinCVSS = %f, want 5.0", opts.MinCVSS)
	}
	if opts.MaxCVSS != 9.0 {
		t.Errorf("MaxCVSS = %f, want 9.0", opts.MaxCVSS)
	}
}

// --- Test StorageManager struct fields ---

func TestStorage_StorageManager_AllFields(t *testing.T) {
	mock := newMockStorage()
	sm := &StorageManager{
		Primary:         mock,
		Cache:           mock,
		CacheEnabled:    true,
		CacheTTLSeconds: 7200,
	}

	if sm.Primary == nil {
		t.Errorf("Primary should not be nil")
	}
	if sm.Cache == nil {
		t.Errorf("Cache should not be nil")
	}
	if !sm.CacheEnabled {
		t.Errorf("CacheEnabled should be true")
	}
	if sm.CacheTTLSeconds != 7200 {
		t.Errorf("CacheTTLSeconds = %d, want 7200", sm.CacheTTLSeconds)
	}
}

// --- Test GetCPE cache error path ---

func TestStorage_GetCPE_CacheError_FallsBackToPrimary(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	mock.cpes[testCPE.GetURI()] = testCPE

	// Cache returns error (miss), primary has it
	result, err := sm.GetCPE(testCPE.GetURI())
	if err != nil {
		t.Errorf("GetCPE() error = %v", err)
	}
	if result.Cpe23 != testCPE.Cpe23 {
		t.Errorf("GetCPE() = %v, want %v", result.Cpe23, testCPE.Cpe23)
	}
}

// --- Test GetCVE cache error path ---

func TestStorage_GetCVE_CacheError_FallsBackToPrimary(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCVE := NewCVEReference("CVE-2021-12345")
	mock.cves[testCVE.CVEID] = testCVE

	// Cache returns error (miss), primary has it
	result, err := sm.GetCVE(testCVE.CVEID)
	if err != nil {
		t.Errorf("GetCVE() error = %v", err)
	}
	if result.CVEID != testCVE.CVEID {
		t.Errorf("GetCVE() = %v, want %v", result.CVEID, testCVE.CVEID)
	}
}

// --- Test StoreCPE with cache that silently fails ---

func TestStorage_StoreCPE_CacheWriteFails(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	cache.storeCPEErr = ErrInvalidData // cache write will fail
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCPE := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	// Primary succeeds, cache error is silently ignored
	err := sm.StoreCPE(testCPE)
	if err != nil {
		t.Errorf("StoreCPE() should not return error when cache fails, got %v", err)
	}
}

// --- Test GetCVE with cache write failure ---

func TestStorage_GetCVE_CacheWriteFailsSilently(t *testing.T) {
	mock := newMockStorage()
	cache := newMockStorage()
	cache.storeCVEErr = ErrInvalidData // cache write will fail
	sm := NewStorageManager(mock)
	sm.SetCache(cache)

	testCVE := NewCVEReference("CVE-2021-12345")
	mock.cves[testCVE.CVEID] = testCVE

	// Cache miss, primary hit, cache write silently fails
	result, err := sm.GetCVE(testCVE.CVEID)
	if err != nil {
		t.Errorf("GetCVE() should not return error when cache write fails, got %v", err)
	}
	if result.CVEID != testCVE.CVEID {
		t.Errorf("GetCVE() = %v, want %v", result.CVEID, testCVE.CVEID)
	}
}
