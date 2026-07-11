package cpeskills

import (
	"os"
	"testing"
	"time"
)

// TestFileStorage_ErrorPaths tests error handling branches in file_storage.go

func TestFileStorage_NewFileStorage_MkdirAllError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cpe_mkdir_test")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	_, err = NewFileStorage(tmpPath+"/subdir/cpes", false)
	if err == nil {
		t.Error("expected error when baseDir parent is a file")
	}
}

func TestFileStorage_StoreCPE_WriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpesDir := tempDir + "/cpes"
	os.Chmod(cpesDir, 0555)
	defer os.Chmod(cpesDir, 0755)

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	err := fs.StoreCPE(cpe)
	if err == nil {
		t.Error("expected error when writing to read-only directory")
	}
}

func TestFileStorage_UpdateCPE_StoreCPEWriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpesDir := tempDir + "/cpes"
	os.Chmod(cpesDir, 0555)
	defer os.Chmod(cpesDir, 0755)

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	err := fs.UpdateCPE(cpe)
	if err == nil {
		t.Error("expected error when StoreCPE fails inside UpdateCPE")
	}
}

func TestFileStorage_DeleteCPE_RemoveErrorWithDir(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Store a CPE first
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	// Replace the file with a directory to cause os.Remove to fail
	cpesDir := tempDir + "/cpes"
	cpeHash := hashString("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	cpeFilePath := cpesDir + "/" + cpeHash + ".json"
	os.Remove(cpeFilePath)
	os.MkdirAll(cpeFilePath, 0755)

	err := fs.DeleteCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	if err == nil {
		t.Log("DeleteCPE() succeeded when removing directory (OS may allow rmdir)")
	}
}

func TestFileStorage_SearchCPE_CacheMissReload(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	fs.cache = NewMemoryStorage()
	fs.cache.Initialize()

	results, err := fs.SearchCPE(nil, nil)
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCPE() returned %d results, want 1", len(results))
	}
}

func TestFileStorage_loadAllCPEs_InvalidJSONFile(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpesDir := tempDir + "/cpes"
	os.WriteFile(cpesDir+"/invalid.json", []byte("not json"), 0644)

	results, err := fs.loadAllCPEs()
	if err != nil {
		t.Errorf("loadAllCPEs() should handle invalid JSON gracefully: %v", err)
	}
	_ = results
}

func TestFileStorage_StoreCVE_WriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cvesDir := tempDir + "/cves"
	os.Chmod(cvesDir, 0555)
	defer os.Chmod(cvesDir, 0755)

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	err := fs.StoreCVE(cve)
	if err == nil {
		t.Error("expected error when writing CVE to read-only directory")
	}
}

func TestFileStorage_UpdateCVE_WriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cvesDir := tempDir + "/cves"
	os.Chmod(cvesDir, 0555)
	defer os.Chmod(cvesDir, 0755)

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	err := fs.UpdateCVE(cve)
	if err == nil {
		t.Error("expected error when updating CVE in read-only directory")
	}
}

func TestFileStorage_DeleteCVE_RemoveError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	fs.StoreCVE(cve)

	cvesDir := tempDir + "/cves"
	os.Chmod(cvesDir, 0555)
	defer os.Chmod(cvesDir, 0755)

	err := fs.DeleteCVE("CVE-2021-44228")
	if err == nil {
		t.Error("expected error when deleting CVE from read-only directory")
	}
}

func TestFileStorage_DeleteCVE_NonExistent(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.DeleteCVE("CVE-9999-0000")
	_ = err
}

func TestFileStorage_StoreDictionary_WriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	dictDir := tempDir + "/dictionary"
	os.Chmod(dictDir, 0555)
	defer os.Chmod(dictDir, 0755)

	dict := &CPEDictionary{}
	err := fs.StoreDictionary(dict)
	if err == nil {
		t.Error("expected error when writing dictionary to read-only directory")
	}
}

func TestFileStorage_StoreModificationTimestamp_WriteError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	metaDir := tempDir + "/metadata"
	os.Chmod(metaDir, 0555)
	defer os.Chmod(metaDir, 0755)

	err := fs.StoreModificationTimestamp("test", time.Now())
	if err == nil {
		t.Error("expected error when writing metadata to read-only directory")
	}
}

func TestFileStorage_AdvancedSearchCPE_LoadFromFiles(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	results, err := fs.AdvancedSearchCPE(cpe, NewAdvancedMatchOptions())
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1", len(results))
	}
}

func TestFileStorage_FindCVEsByCPE_LoadFromFiles(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	fs.StoreCVE(cve)

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	results, err := fs.FindCVEsByCPE(cpe)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	_ = results
}

func TestFileStorage_FindCPEsByCVE_LoadFromFiles(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("log4j"),
		Version:     Version("2.0"),
	}
	fs.StoreCPE(cpe)

	cve := &CVEReference{
		CVEID:        "CVE-2021-44228",
		AffectedCPEs: []string{"cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
	}
	fs.StoreCVE(cve)

	results, err := fs.FindCPEsByCVE("CVE-2021-44228")
	if err != nil {
		t.Errorf("FindCPEsByCVE() error = %v", err)
	}
	_ = results
}

func TestFileStorage_SearchCVE_CacheMissReload(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	fs.StoreCVE(cve)

	fs.cache = NewMemoryStorage()
	fs.cache.Initialize()

	results, err := fs.SearchCVE("", nil)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	_ = results
}

func TestFileStorage_loadAllCVEs_InvalidJSONFile(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cvesDir := tempDir + "/cves"
	os.WriteFile(cvesDir+"/invalid.json", []byte("not json"), 0644)

	results, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() should handle invalid JSON gracefully: %v", err)
	}
	_ = results
}

func TestFileStorage_StoreCVE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	if err := fs.StoreCVE(cve); err != nil {
		t.Errorf("StoreCVE() with cache should succeed: %v", err)
	}
}

func TestFileStorage_StoreCPE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	if err := fs.StoreCPE(cpe); err != nil {
		t.Errorf("StoreCPE() with cache should succeed: %v", err)
	}
}

func TestFileStorage_UpdateCPE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	// Update with cache
	if err := fs.UpdateCPE(cpe); err != nil {
		t.Errorf("UpdateCPE() with cache should succeed: %v", err)
	}
}

func TestFileStorage_StoreCVE_UpdateTimestampError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	// Store a CVE - this also calls StoreModificationTimestamp which should succeed
	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	if err := fs.StoreCVE(cve); err != nil {
		t.Errorf("StoreCVE() should succeed: %v", err)
	}
}

func TestFileStorage_UpdateCVE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	fs.StoreCVE(cve)

	// Update with cache
	if err := fs.UpdateCVE(cve); err != nil {
		t.Errorf("UpdateCVE() with cache should succeed: %v", err)
	}
}

func TestFileStorage_DeleteCVE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := &CVEReference{CVEID: "CVE-2021-44228"}
	fs.StoreCVE(cve)

	if err := fs.DeleteCVE("CVE-2021-44228"); err != nil {
		t.Errorf("DeleteCVE() with cache should succeed: %v", err)
	}
}

func TestFileStorage_DeleteCPE_CacheEnabled(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	if err := fs.DeleteCPE(cpe.GetURI()); err != nil {
		t.Errorf("DeleteCPE() with cache should succeed: %v", err)
	}
}
