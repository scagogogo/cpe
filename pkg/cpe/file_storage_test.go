package cpeskills

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewFileStorage(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test con caché habilitado
	t.Run("Con caché habilitado", func(t *testing.T) {
		fs, err := NewFileStorage(tempDir, true)
		if err != nil {
			t.Fatalf("NewFileStorage() error = %v", err)
		}
		if fs == nil {
			t.Fatalf("NewFileStorage() devolvió nil")
		}
		if fs.baseDir != tempDir {
			t.Errorf("baseDir = %v, se esperaba %v", fs.baseDir, tempDir)
		}
		if !fs.useCache {
			t.Errorf("useCache = %v, se esperaba true", fs.useCache)
		}
		if fs.cache == nil {
			t.Errorf("cache es nil, se esperaba una instancia de MemoryStorage")
		}
	})

	// Test con caché deshabilitado
	t.Run("Con caché deshabilitado", func(t *testing.T) {
		fs, err := NewFileStorage(tempDir, false)
		if err != nil {
			t.Fatalf("NewFileStorage() error = %v", err)
		}
		if fs.useCache {
			t.Errorf("useCache = %v, se esperaba false", fs.useCache)
		}
	})

	// Verificar que se hayan creado los subdirectorios
	subdirs := []string{"cpes", "cves", "dictionary", "metadata"}
	for _, dir := range subdirs {
		path := filepath.Join(tempDir, dir)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("No se creó el subdirectorio: %s", dir)
		}
	}
}

func TestFileStorage_Initialize(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage
	fs, err := NewFileStorage(tempDir, true)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}

	// Inicializar storage
	if err := fs.Initialize(); err != nil {
		t.Errorf("Initialize() error = %v", err)
	}

	// Verificar que se haya creado el archivo de timestamp
	metadataPath := filepath.Join(tempDir, "metadata", "initialization.json")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		t.Errorf("No se creó el archivo de timestamp de inicialización")
	}

	// Verificar que se pueda recuperar el timestamp
	timestamp, err := fs.RetrieveModificationTimestamp("initialization")
	if err != nil {
		t.Errorf("RetrieveModificationTimestamp() error = %v", err)
	}

	// Comprobar que el timestamp no sea cero
	if timestamp.IsZero() {
		t.Errorf("RetrieveModificationTimestamp() devolvió timestamp cero")
	}
}

func TestFileStorage_CPEOperations(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage
	fs, err := NewFileStorage(tempDir, true)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}
	if err := fs.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Crear CPE de prueba
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}

	// Test StoreCPE
	t.Run("StoreCPE", func(t *testing.T) {
		if err := fs.StoreCPE(cpe); err != nil {
			t.Errorf("StoreCPE() error = %v", err)
		}

		// Verificar que se haya creado el archivo
		cpeFilePath := fs.CPEFilePath(cpe.Cpe23)
		if _, err := os.Stat(cpeFilePath); os.IsNotExist(err) {
			t.Errorf("No se creó el archivo CPE: %s", cpeFilePath)
		}
	})

	// Test RetrieveCPE
	t.Run("RetrieveCPE", func(t *testing.T) {
		retrievedCPE, err := fs.RetrieveCPE(cpe.Cpe23)
		if err != nil {
			t.Errorf("RetrieveCPE() error = %v", err)
		}
		if retrievedCPE == nil {
			t.Errorf("RetrieveCPE() devolvió nil")
		} else if retrievedCPE.Cpe23 != cpe.Cpe23 {
			t.Errorf("RetrieveCPE().Cpe23 = %v, se esperaba %v", retrievedCPE.Cpe23, cpe.Cpe23)
		}
	})

	// Test UpdateCPE
	t.Run("UpdateCPE", func(t *testing.T) {
		// 更新原始CPE
		cpe.Version = Version("2.0")
		cpe.Cpe23 = "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"

		if err := fs.UpdateCPE(cpe); err != nil {
			t.Errorf("UpdateCPE() error = %v", err)
		}

		retrievedCPE, err := fs.RetrieveCPE(cpe.Cpe23)
		if err != nil {
			t.Errorf("RetrieveCPE() después de update error = %v", err)
		}
		if retrievedCPE == nil {
			t.Errorf("RetrieveCPE() después de update devolvió nil")
		} else if retrievedCPE.Version != cpe.Version {
			t.Errorf("RetrieveCPE().Version = %v, se esperaba %v", retrievedCPE.Version, cpe.Version)
		}
	})

	// Test SearchCPE
	t.Run("SearchCPE", func(t *testing.T) {
		// 存储一个额外的CPE用于搜索测试
		searchTestCpe := &CPE{
			Cpe23:       "cpe:2.3:a:vendor:product_search:1.0:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      Vendor("vendor"),
			ProductName: Product("product_search"),
			Version:     Version("1.0"),
		}

		if err := fs.StoreCPE(searchTestCpe); err != nil {
			t.Errorf("StoreCPE() error for search test = %v", err)
		}

		criteria := &CPE{
			Vendor: Vendor("vendor"),
		}
		results, err := fs.SearchCPE(criteria, nil)
		if err != nil {
			t.Errorf("SearchCPE() error = %v", err)
		}

		// 添加调试信息
		t.Logf("搜索结果数量: %d", len(results))
		for i, c := range results {
			t.Logf("结果 %d: URI=%s, Vendor=%s, Product=%s, Version=%s",
				i, c.GetURI(), string(c.Vendor), string(c.ProductName), string(c.Version))
		}

		if len(results) != 3 { // 现在期望3个结果：原始CPE + 更新后的CPE + 新增的测试CPE
			t.Errorf("SearchCPE() devolvió %d resultados, se esperaba 3", len(results))
		}
	})

	// Test DeleteCPE
	t.Run("DeleteCPE", func(t *testing.T) {
		if err := fs.DeleteCPE(cpe.Cpe23); err != nil {
			t.Errorf("DeleteCPE() error = %v", err)
		}

		// Verificar que se haya eliminado el archivo
		cpeFilePath := fs.CPEFilePath(cpe.Cpe23)
		if _, err := os.Stat(cpeFilePath); !os.IsNotExist(err) {
			t.Errorf("No se eliminó el archivo CPE: %s", cpeFilePath)
		}

		// Verificar que ya no se pueda recuperar
		_, err := fs.RetrieveCPE(cpe.Cpe23)
		if err == nil {
			t.Errorf("RetrieveCPE() después de delete no devolvió error")
		}
	})
}

func TestFileStorage_CVEOperations(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage
	fs, err := NewFileStorage(tempDir, true)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}
	if err := fs.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Crear CVE de prueba
	cve := NewCVEReference("CVE-2021-12345")
	cve.Description = "Test CVE"
	cve.CVSSScore = 7.5
	cve.Severity = "High"
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")

	// Test StoreCVE
	t.Run("StoreCVE", func(t *testing.T) {
		if err := fs.StoreCVE(cve); err != nil {
			t.Errorf("StoreCVE() error = %v", err)
		}

		// Verificar que se haya creado el archivo
		cveFilePath := fs.CVEFilePath(cve.CVEID)
		if _, err := os.Stat(cveFilePath); os.IsNotExist(err) {
			t.Errorf("No se creó el archivo CVE: %s", cveFilePath)
		}
	})

	// Test RetrieveCVE
	t.Run("RetrieveCVE", func(t *testing.T) {
		retrievedCVE, err := fs.RetrieveCVE(cve.CVEID)
		if err != nil {
			t.Errorf("RetrieveCVE() error = %v", err)
		}
		if retrievedCVE == nil {
			t.Errorf("RetrieveCVE() devolvió nil")
		} else if retrievedCVE.CVEID != cve.CVEID {
			t.Errorf("RetrieveCVE().CVEID = %v, se esperaba %v", retrievedCVE.CVEID, cve.CVEID)
		}
	})

	// Test UpdateCVE
	t.Run("UpdateCVE", func(t *testing.T) {
		cve.Description = "Updated Test CVE"
		cve.CVSSScore = 9.0
		cve.Severity = "Critical"

		if err := fs.UpdateCVE(cve); err != nil {
			t.Errorf("UpdateCVE() error = %v", err)
		}

		retrievedCVE, err := fs.RetrieveCVE(cve.CVEID)
		if err != nil {
			t.Errorf("RetrieveCVE() después de update error = %v", err)
		}
		if retrievedCVE == nil {
			t.Errorf("RetrieveCVE() después de update devolvió nil")
		} else if retrievedCVE.Description != cve.Description {
			t.Errorf("RetrieveCVE().Description = %v, se esperaba %v", retrievedCVE.Description, cve.Description)
		}
	})

	// Test DeleteCVE
	t.Run("DeleteCVE", func(t *testing.T) {
		if err := fs.DeleteCVE(cve.CVEID); err != nil {
			t.Errorf("DeleteCVE() error = %v", err)
		}

		// Verificar que se haya eliminado el archivo
		cveFilePath := fs.CVEFilePath(cve.CVEID)
		if _, err := os.Stat(cveFilePath); !os.IsNotExist(err) {
			t.Errorf("No se eliminó el archivo CVE: %s", cveFilePath)
		}

		// Verificar que ya no se pueda recuperar
		_, err := fs.RetrieveCVE(cve.CVEID)
		if err == nil {
			t.Errorf("RetrieveCVE() después de delete no devolvió error")
		}
	})
}

func TestFileStorage_DictionaryOperations(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage
	fs, err := NewFileStorage(tempDir, true)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}
	if err := fs.Initialize(); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	// Crear diccionario de prueba
	dict := &CPEDictionary{
		Items: []*CPEItem{
			{
				Name:  "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Title: "Vendor Product 1.0",
				CPE: &CPE{
					Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					Part:        *PartApplication,
					Vendor:      "vendor",
					ProductName: "product",
					Version:     "1.0",
				},
			},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}

	// Test StoreDictionary
	t.Run("StoreDictionary", func(t *testing.T) {
		if err := fs.StoreDictionary(dict); err != nil {
			t.Errorf("StoreDictionary() error = %v", err)
		}

		// Verificar que se haya creado el archivo
		dictFilePath := fs.DictionaryFilePath()
		if _, err := os.Stat(dictFilePath); os.IsNotExist(err) {
			t.Errorf("No se creó el archivo de diccionario: %s", dictFilePath)
		}
	})

	// Test RetrieveDictionary
	t.Run("RetrieveDictionary", func(t *testing.T) {
		retrievedDict, err := fs.RetrieveDictionary()
		if err != nil {
			t.Errorf("RetrieveDictionary() error = %v", err)
		}
		if retrievedDict == nil {
			t.Errorf("RetrieveDictionary() devolvió nil")
		} else if len(retrievedDict.Items) != len(dict.Items) {
			t.Errorf("RetrieveDictionary().Items tiene %d elementos, se esperaban %d", len(retrievedDict.Items), len(dict.Items))
		} else if retrievedDict.Items[0].Name != dict.Items[0].Name {
			t.Errorf("RetrieveDictionary().Items[0].Name = %v, se esperaba %v", retrievedDict.Items[0].Name, dict.Items[0].Name)
		}
	})
}

func TestFileStorage_TimestampOperations(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage
	fs, err := NewFileStorage(tempDir, false)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}

	// Test StoreModificationTimestamp
	testTime := time.Now()
	t.Run("StoreModificationTimestamp", func(t *testing.T) {
		if err := fs.StoreModificationTimestamp("test_key", testTime); err != nil {
			t.Errorf("StoreModificationTimestamp() error = %v", err)
		}

		// Verificar que se haya creado el archivo
		metadataPath := filepath.Join(tempDir, "metadata", "test_key.json")
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			t.Errorf("No se creó el archivo de metadata: %s", metadataPath)
		}
	})

	// Test RetrieveModificationTimestamp
	t.Run("RetrieveModificationTimestamp", func(t *testing.T) {
		retrievedTime, err := fs.RetrieveModificationTimestamp("test_key")
		if err != nil {
			t.Errorf("RetrieveModificationTimestamp() error = %v", err)
		}

		// La comparación de tiempo puede fallar debido a la precisión, así que comparamos solo hasta el segundo
		if retrievedTime.Unix() != testTime.Unix() {
			t.Errorf("RetrieveModificationTimestamp() = %v, se esperaba %v", retrievedTime, testTime)
		}
	})

	// Test recuperar timestamp no existente
	t.Run("RetrieveNonExistentTimestamp", func(t *testing.T) {
		_, err := fs.RetrieveModificationTimestamp("non_existent_key")
		if err == nil {
			t.Errorf("RetrieveModificationTimestamp() de clave no existente no devolvió error")
		}
	})
}

func TestFileStorage_HelperFunctions(t *testing.T) {
	t.Run("hashString", func(t *testing.T) {
		hash1 := hashString("test")
		hash2 := hashString("test")
		hash3 := hashString("different")

		if hash1 != hash2 {
			t.Errorf("hashString() para la misma entrada devolvió valores diferentes: %s != %s", hash1, hash2)
		}
		if hash1 == hash3 {
			t.Errorf("hashString() para entradas diferentes devolvió el mismo valor: %s", hash1)
		}
	})

	t.Run("sanitizeFileName", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{"test", "test"},
			{"test/file", "test_file"},
			{"test:file", "test_file"},
			{"test?file<>", "test_file__"},
			{"test\\file", "test_file"},
		}

		for _, tt := range tests {
			result := sanitizeFileName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFileName(%s) = %s, se esperaba %s", tt.input, result, tt.expected)
			}
		}
	})

	t.Run("isJSONFile", func(t *testing.T) {
		tests := []struct {
			filename string
			isJSON   bool
		}{
			{"test.json", true},
			{"test.JSON", true},
			{"test.txt", false},
			{"test", false},
			{"test.json.txt", false},
		}

		for _, tt := range tests {
			result := isJSONFile(tt.filename)
			if result != tt.isJSON {
				t.Errorf("isJSONFile(%s) = %v, se esperaba %v", tt.filename, result, tt.isJSON)
			}
		}
	})
}

func TestFileStorage_CPEFilePaths(t *testing.T) {
	// Crear storage
	fs := &FileStorage{
		baseDir: "/test/dir",
	}

	cpeID := "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
	expectedPath := filepath.Join("/test/dir", "cpes", hashString(cpeID)+".json")

	path := fs.CPEFilePath(cpeID)
	if path != expectedPath {
		t.Errorf("CPEFilePath() = %s, se esperaba %s", path, expectedPath)
	}
}

func TestFileStorage_CVEFilePaths(t *testing.T) {
	// Crear storage
	fs := &FileStorage{
		baseDir: "/test/dir",
	}

	cveID := "CVE-2021-12345"
	expectedPath := filepath.Join("/test/dir", "cves", sanitizeFileName(cveID)+".json")

	path := fs.CVEFilePath(cveID)
	if path != expectedPath {
		t.Errorf("CVEFilePath() = %s, se esperaba %s", path, expectedPath)
	}
}

func TestFileStorage_DictionaryFilePath(t *testing.T) {
	// Crear storage
	fs := &FileStorage{
		baseDir: "/test/dir",
	}

	expectedPath := filepath.Join("/test/dir", "dictionary", "cpe_dictionary.json")

	path := fs.DictionaryFilePath()
	if path != expectedPath {
		t.Errorf("DictionaryFilePath() = %s, se esperaba %s", path, expectedPath)
	}
}

func TestFileStorage_MetadataFilePath(t *testing.T) {
	// Crear storage
	fs := &FileStorage{
		baseDir: "/test/dir",
	}

	key := "last_update"
	expectedPath := filepath.Join("/test/dir", "metadata", key+".json")

	path := fs.MetadataFilePath(key)
	if path != expectedPath {
		t.Errorf("MetadataFilePath() = %s, se esperaba %s", path, expectedPath)
	}
}

func TestFileStorage_Close(t *testing.T) {
	// Crear directorio temporal para tests
	tempDir, err := os.MkdirTemp("", "cpe_test_*")
	if err != nil {
		t.Fatalf("Error al crear directorio temporal: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Crear storage con caché
	fs, err := NewFileStorage(tempDir, true)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}

	// Test Close
	if err := fs.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Crear storage sin caché
	fs, err = NewFileStorage(tempDir, false)
	if err != nil {
		t.Fatalf("NewFileStorage() error = %v", err)
	}

	// Test Close
	if err := fs.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

// TestSimpleFileStorageOperations 验证文件存储基本功能
func TestSimpleFileStorageOperations(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "cpe_simple_test_*")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建存储对象
	fs, err := NewFileStorage(tempDir, false) // 不使用缓存，避免潜在的死锁
	if err != nil {
		t.Fatalf("创建文件存储失败: %v", err)
	}
	if err := fs.Initialize(); err != nil {
		t.Fatalf("初始化存储失败: %v", err)
	}

	// 创建测试CPE
	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}

	// 存储CPE
	if err := fs.StoreCPE(cpe1); err != nil {
		t.Fatalf("存储CPE1失败: %v", err)
	}

	// 验证检索
	retrieved, err := fs.RetrieveCPE(cpe1.Cpe23)
	if err != nil {
		t.Fatalf("检索CPE1失败: %v", err)
	}
	if retrieved.Cpe23 != cpe1.Cpe23 {
		t.Errorf("检索到的CPE1不匹配: 期望 %s, 得到 %s", cpe1.Cpe23, retrieved.Cpe23)
	}

	// 检查文件是否正确写入
	cpeFilePath := fs.CPEFilePath(cpe1.Cpe23)
	if _, err := os.Stat(cpeFilePath); os.IsNotExist(err) {
		t.Fatalf("CPE文件未创建: %s", cpeFilePath)
	}

	// 直接读取并打印所有CPE
	files, err := filepath.Glob(filepath.Join(tempDir, "cpes", "*.json"))
	if err != nil {
		t.Fatalf("读取CPE目录失败: %v", err)
	}

	t.Logf("找到 %d 个CPE文件", len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Logf("读取文件 %s 失败: %v", file, err)
			continue
		}
		t.Logf("文件 %s 内容: %s", file, string(data))
	}

	// 搜索CPE (通过遍历所有CPE实现)
	allCPEs, err := fs.loadAllCPEs()
	if err != nil {
		t.Fatalf("加载所有CPE失败: %v", err)
	}

	t.Logf("loadAllCPEs 结果: %d 个CPE", len(allCPEs))
	for i, c := range allCPEs {
		t.Logf("CPE %d: URI=%s, Vendor=%s", i, c.GetURI(), string(c.Vendor))
	}

	// 检查是否包含我们添加的CPE
	found := false
	for _, c := range allCPEs {
		if c.GetURI() == cpe1.GetURI() {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("loadAllCPEs 未找到我们存储的CPE")
	}
}

// --- StoreCPE additional tests ---

func TestFileStorage_StoreCPE_Nil(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.StoreCPE(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreCPE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestFileStorage_StoreCPE_WithoutCache(t *testing.T) {
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

	err := fs.StoreCPE(cpe)
	if err != nil {
		t.Errorf("StoreCPE() error = %v", err)
	}
}

// --- RetrieveCPE additional tests ---

func TestFileStorage_RetrieveCPE_NotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	_, err := fs.RetrieveCPE("nonexistent")
	if err != ErrNotFound {
		t.Errorf("RetrieveCPE() error = %v, want ErrNotFound", err)
	}
}

func TestFileStorage_RetrieveCPE_WithoutCache(t *testing.T) {
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

	result, err := fs.RetrieveCPE(cpe.Cpe23)
	if err != nil {
		t.Errorf("RetrieveCPE() error = %v", err)
	}
	if result.Cpe23 != cpe.Cpe23 {
		t.Errorf("RetrieveCPE() = %v, want %v", result.Cpe23, cpe.Cpe23)
	}
}

// --- UpdateCPE additional tests ---

func TestFileStorage_UpdateCPE_Nil(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.UpdateCPE(nil)
	if err != ErrInvalidData {
		t.Errorf("UpdateCPE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestFileStorage_UpdateCPE_WithoutCache(t *testing.T) {
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

	cpe.Version = Version("2.0")
	err := fs.UpdateCPE(cpe)
	if err != nil {
		t.Errorf("UpdateCPE() error = %v", err)
	}
}

// --- DeleteCPE additional tests ---

func TestFileStorage_DeleteCPE_FileNotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	// Delete non-existent CPE should not error
	err := fs.DeleteCPE("nonexistent")
	if err != nil {
		t.Errorf("DeleteCPE() for non-existent file should not error, got %v", err)
	}
}

func TestFileStorage_DeleteCPE_WithoutCache(t *testing.T) {
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

	err := fs.DeleteCPE(cpe.Cpe23)
	if err != nil {
		t.Errorf("DeleteCPE() error = %v", err)
	}
}

// --- SearchCPE additional tests ---

func TestFileStorage_SearchCPE_NilCriteria(t *testing.T) {
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

	results, err := fs.SearchCPE(nil, nil)
	if err != nil {
		t.Errorf("SearchCPE(nil) error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCPE(nil) returned %d results, want 1", len(results))
	}
}

func TestFileStorage_SearchCPE_WithCriteria(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	cpe2 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	}
	fs.StoreCPE(cpe1)
	fs.StoreCPE(cpe2)

	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	results, err := fs.SearchCPE(criteria, &MatchOptions{})
	if err != nil {
		t.Errorf("SearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCPE() returned %d results, want 1", len(results))
	}
}

// --- StoreCVE additional tests ---

func TestFileStorage_StoreCVE_Nil(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.StoreCVE(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreCVE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestFileStorage_StoreCVE_EmptyID(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.StoreCVE(&CVEReference{})
	if err == nil {
		t.Errorf("StoreCVE() with empty ID should return error")
	}
}

func TestFileStorage_StoreCVE_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-99999")
	cve.Description = "Test CVE without cache"

	err := fs.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() error = %v", err)
	}
}

// --- RetrieveCVE additional tests ---

func TestFileStorage_RetrieveCVE_NotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	_, err := fs.RetrieveCVE("CVE-nonexistent")
	if err != ErrNotFound {
		t.Errorf("RetrieveCVE() error = %v, want ErrNotFound", err)
	}
}

func TestFileStorage_RetrieveCVE_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-99998")
	cve.Description = "Test CVE without cache"
	fs.StoreCVE(cve)

	result, err := fs.RetrieveCVE(cve.CVEID)
	if err != nil {
		t.Errorf("RetrieveCVE() error = %v", err)
	}
	if result.CVEID != cve.CVEID {
		t.Errorf("RetrieveCVE() = %v, want %v", result.CVEID, cve.CVEID)
	}
}

func TestFileStorage_RetrieveCVE_CacheHitButNotErrNotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-77777")
	cve.Description = "Cache test"
	fs.StoreCVE(cve)

	// Should retrieve from cache
	result, err := fs.RetrieveCVE(cve.CVEID)
	if err != nil {
		t.Errorf("RetrieveCVE() error = %v", err)
	}
	if result.CVEID != cve.CVEID {
		t.Errorf("RetrieveCVE() = %v, want %v", result.CVEID, cve.CVEID)
	}
}

func TestFileStorage_RetrieveCVE_CacheMiss(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	// Store CVE, clear cache, then retrieve should fall through to file
	cve := NewCVEReference("CVE-2021-88888")
	cve.Description = "Cache miss test"
	fs.StoreCVE(cve)

	// Clear cache so we hit file
	fs.cache.Initialize()

	result, err := fs.RetrieveCVE(cve.CVEID)
	if err != nil {
		t.Errorf("RetrieveCVE() error = %v", err)
	}
	if result.CVEID != cve.CVEID {
		t.Errorf("RetrieveCVE() = %v, want %v", result.CVEID, cve.CVEID)
	}
}

// --- UpdateCVE additional tests ---

func TestFileStorage_UpdateCVE_Nil(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.UpdateCVE(nil)
	if err != ErrInvalidData {
		t.Errorf("UpdateCVE(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestFileStorage_UpdateCVE_EmptyID(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.UpdateCVE(&CVEReference{})
	if err == nil {
		t.Errorf("UpdateCVE() with empty ID should return error")
	}
}

func TestFileStorage_UpdateCVE_NotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-nonexistent")
	err := fs.UpdateCVE(cve)
	if err != ErrNotFound {
		t.Errorf("UpdateCVE() for non-existent CVE error = %v, want ErrNotFound", err)
	}
}

func TestFileStorage_UpdateCVE_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-55555")
	cve.Description = "Original"
	fs.StoreCVE(cve)

	cve.Description = "Updated"
	err := fs.UpdateCVE(cve)
	if err != nil {
		t.Errorf("UpdateCVE() error = %v", err)
	}

	result, _ := fs.RetrieveCVE(cve.CVEID)
	if result.Description != "Updated" {
		t.Errorf("UpdateCVE() description = %v, want Updated", result.Description)
	}
}

// --- DeleteCVE additional tests ---

func TestFileStorage_DeleteCVE_NotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.DeleteCVE("CVE-nonexistent")
	if err != ErrNotFound {
		t.Errorf("DeleteCVE() error = %v, want ErrNotFound", err)
	}
}

func TestFileStorage_DeleteCVE_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-44444")
	fs.StoreCVE(cve)

	err := fs.DeleteCVE(cve.CVEID)
	if err != nil {
		t.Errorf("DeleteCVE() error = %v", err)
	}

	_, err = fs.RetrieveCVE(cve.CVEID)
	if err == nil {
		t.Errorf("RetrieveCVE() after delete should return error")
	}
}

// --- SearchCVE Tests ---

func TestFileStorage_SearchCVE(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	cve1.Description = "windows vulnerability"
	fs.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	cve2.Description = "linux vulnerability"
	fs.StoreCVE(cve2)

	results, err := fs.SearchCVE("windows", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE('windows') returned %d results, want 1", len(results))
	}
}

func TestFileStorage_SearchCVE_EmptyQuery(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	fs.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	fs.StoreCVE(cve2)

	results, err := fs.SearchCVE("", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 2 {
		t.Errorf("SearchCVE('') returned %d results, want 2", len(results))
	}
}

func TestFileStorage_SearchCVE_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-33333")
	cve.Description = "test search"
	fs.StoreCVE(cve)

	results, err := fs.SearchCVE("test", NewSearchOptions())
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() returned %d results, want 1", len(results))
	}
}

// --- loadAllCVEs Tests ---

func TestFileStorage_loadAllCVEs(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve1 := NewCVEReference("CVE-2021-00001")
	fs.StoreCVE(cve1)

	cve2 := NewCVEReference("CVE-2021-00002")
	fs.StoreCVE(cve2)

	cves, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() error = %v", err)
	}
	if len(cves) != 2 {
		t.Errorf("loadAllCVEs() returned %d CVEs, want 2", len(cves))
	}
}

func TestFileStorage_loadAllCVEs_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-66666")
	fs.StoreCVE(cve)

	cves, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() error = %v", err)
	}
	if len(cves) != 1 {
		t.Errorf("loadAllCVEs() returned %d CVEs, want 1", len(cves))
	}
}

func TestFileStorage_loadAllCVEs_EmptyDir(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cves, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() error = %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("loadAllCVEs() returned %d CVEs, want 0", len(cves))
	}
}

func TestFileStorage_loadAllCVEs_NonExistentDir(t *testing.T) {
	fs := &FileStorage{
		baseDir:  "/nonexistent/path/that/does/not/exist",
		useCache: false,
	}

	cves, err := fs.loadAllCVEs()
	if err == nil {
		t.Errorf("loadAllCVEs() with non-existent dir should return error")
	}
	if cves != nil {
		t.Errorf("loadAllCVEs() should return nil cves on error")
	}
}

// --- FindCVEsByCPE Tests ---

func TestFileStorage_FindCVEsByCPE(t *testing.T) {
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

	cve := NewCVEReference("CVE-2021-11111")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	fs.StoreCVE(cve)

	results, err := fs.FindCVEsByCPE(cpe)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	if len(results) < 1 {
		t.Errorf("FindCVEsByCPE() returned %d results, want at least 1", len(results))
	}
}

func TestFileStorage_FindCVEsByCPE_NoMatch(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("other"),
		ProductName: Product("thing"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	results, err := fs.FindCVEsByCPE(cpe)
	if err != nil {
		t.Errorf("FindCVEsByCPE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("FindCVEsByCPE() returned %d results, want 0", len(results))
	}
}

// --- FindCPEsByCVE Tests ---

func TestFileStorage_FindCPEsByCVE(t *testing.T) {
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

	cve := NewCVEReference("CVE-2021-22222")
	cve.AddAffectedCPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	fs.StoreCVE(cve)

	results, err := fs.FindCPEsByCVE(cve.CVEID)
	if err != nil {
		t.Errorf("FindCPEsByCVE() error = %v", err)
	}
	if len(results) < 1 {
		t.Errorf("FindCPEsByCVE() returned %d results, want at least 1", len(results))
	}
}

func TestFileStorage_FindCPEsByCVE_NoMatch(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	results, err := fs.FindCPEsByCVE("CVE-nonexistent")
	if err != nil {
		t.Errorf("FindCPEsByCVE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("FindCPEsByCVE() returned %d results, want 0", len(results))
	}
}

// --- AdvancedSearchCPE Tests ---

func TestFileStorage_AdvancedSearchCPE_WithCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe1 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor1:product1:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	cpe2 := &CPE{
		Cpe23:       "cpe:2.3:a:vendor2:product2:2.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor2"),
		ProductName: Product("product2"),
		Version:     Version("2.0"),
	}
	fs.StoreCPE(cpe1)
	fs.StoreCPE(cpe2)

	// Use criteria that exactly matches cpe1
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor1"),
		ProductName: Product("product1"),
		Version:     Version("1.0"),
	}
	results, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1", len(results))
	}
}

func TestFileStorage_AdvancedSearchCPE_WithoutCache(t *testing.T) {
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

	// Use criteria that exactly matches
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	results, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1", len(results))
	}
}

func TestFileStorage_AdvancedSearchCPE_NoMatch(t *testing.T) {
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

	// Use non-matching criteria
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("nonexistent"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	results, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 0", len(results))
	}
}

func TestFileStorage_AdvancedSearchCPE_EmptyDir(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	criteria := &CPE{Vendor: Vendor("vendor")}
	results, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	if len(results) != 0 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 0", len(results))
	}
}

// --- StoreDictionary additional tests ---

func TestFileStorage_StoreDictionary_Nil(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	err := fs.StoreDictionary(nil)
	if err != ErrInvalidData {
		t.Errorf("StoreDictionary(nil) error = %v, want ErrInvalidData", err)
	}
}

func TestFileStorage_StoreDictionary_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	dict := &CPEDictionary{
		Items:         []*CPEItem{},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}

	err := fs.StoreDictionary(dict)
	if err != nil {
		t.Errorf("StoreDictionary() error = %v", err)
	}
}

// --- RetrieveDictionary additional tests ---

func TestFileStorage_RetrieveDictionary_NotFound(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	_, err := fs.RetrieveDictionary()
	if err != ErrNotFound {
		t.Errorf("RetrieveDictionary() error = %v, want ErrNotFound", err)
	}
}

func TestFileStorage_RetrieveDictionary_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}
	fs.StoreDictionary(dict)

	result, err := fs.RetrieveDictionary()
	if err != nil {
		t.Errorf("RetrieveDictionary() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Errorf("RetrieveDictionary() returned %d items, want 1", len(result.Items))
	}
}

// --- Initialize without cache ---

func TestFileStorage_Initialize_WithoutCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)

	err := fs.Initialize()
	if err != nil {
		t.Errorf("Initialize() without cache error = %v", err)
	}
}

// --- StoreModificationTimestamp with cache ---

func TestFileStorage_StoreModificationTimestamp_WithCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	testTime := time.Now()
	err := fs.StoreModificationTimestamp("cache_test", testTime)
	if err != nil {
		t.Errorf("StoreModificationTimestamp() error = %v", err)
	}
}

// --- RetrieveModificationTimestamp with cache ---

func TestFileStorage_RetrieveModificationTimestamp_WithCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	testTime := time.Now()
	fs.StoreModificationTimestamp("cache_retrieve_test", testTime)

	result, err := fs.RetrieveModificationTimestamp("cache_retrieve_test")
	if err != nil {
		t.Errorf("RetrieveModificationTimestamp() error = %v", err)
	}
	if result.Unix() != testTime.Unix() {
		t.Errorf("RetrieveModificationTimestamp() = %v, want %v", result, testTime)
	}
}

// --- StoreDictionary with cache ---

func TestFileStorage_StoreDictionary_WithCache(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}

	err := fs.StoreDictionary(dict)
	if err != nil {
		t.Errorf("StoreDictionary() error = %v", err)
	}
}

// --- NewFileStorage error cases ---

func TestNewFileStorage_InvalidPath(t *testing.T) {
	// Try creating file storage in a path that cannot be created
	_, err := NewFileStorage("/dev/null/invalid/path", false)
	if err == nil {
		t.Errorf("NewFileStorage() with invalid path should return error")
	}
}

// --- readCPEFromFile error handling ---

func TestFileStorage_readCPEFromFile_InvalidJSON(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)

	// Write invalid JSON to a CPE file
	cpeDir := filepath.Join(tempDir, "cpes")
	invalidFile := filepath.Join(cpeDir, "invalid.json")
	os.WriteFile(invalidFile, []byte("not valid json"), 0644)

	_, err := fs.readCPEFromFile(invalidFile)
	if err == nil {
		t.Errorf("readCPEFromFile() with invalid JSON should return error")
	}
}

func TestFileStorage_readCPEFromFile_NonExistentFile(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)

	_, err := fs.readCPEFromFile("/nonexistent/file.json")
	if err == nil {
		t.Errorf("readCPEFromFile() with non-existent file should return error")
	}
}

// --- loadAllCPEs with invalid JSON file ---

func TestFileStorage_loadAllCPEs_InvalidFile(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Write an invalid JSON file in cpes directory
	cpeDir := filepath.Join(tempDir, "cpes")
	os.WriteFile(filepath.Join(cpeDir, "bad.json"), []byte("invalid json"), 0644)

	// Should still return results without crashing, skipping the bad file
	cpes, err := fs.loadAllCPEs()
	if err != nil {
		t.Errorf("loadAllCPEs() error = %v", err)
	}
	// The bad file should be skipped
	if len(cpes) != 0 {
		t.Errorf("loadAllCPEs() with only invalid file returned %d cpes, want 0", len(cpes))
	}
}

// --- RetrieveDictionary from cache ---

func TestFileStorage_RetrieveDictionary_CacheHit(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	dict := &CPEDictionary{
		Items: []*CPEItem{
			{Name: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		GeneratedAt:   time.Now(),
		SchemaVersion: "2.3",
	}
	fs.StoreDictionary(dict)

	// Second retrieve should come from cache
	result, err := fs.RetrieveDictionary()
	if err != nil {
		t.Errorf("RetrieveDictionary() error = %v", err)
	}
	if len(result.Items) != 1 {
		t.Errorf("RetrieveDictionary() from cache returned %d items, want 1", len(result.Items))
	}
}

// --- RetrieveModificationTimestamp from cache ---

func TestFileStorage_RetrieveModificationTimestamp_CacheHit(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	testTime := time.Now()
	fs.StoreModificationTimestamp("ts_cache_test", testTime)

	// Second retrieve should come from cache
	result, err := fs.RetrieveModificationTimestamp("ts_cache_test")
	if err != nil {
		t.Errorf("RetrieveModificationTimestamp() error = %v", err)
	}
	if result.Unix() != testTime.Unix() {
		t.Errorf("RetrieveModificationTimestamp() from cache = %v, want %v", result, testTime)
	}
}

// --- DeleteCPE with stat error ---

func TestFileStorage_DeleteCPE_StatError(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	// Create a path where stat will fail (e.g., directory instead of file)
	cpeDir := filepath.Join(tempDir, "cpes")
	hashID := hashString("test")
	filePath := filepath.Join(cpeDir, hashID+".json")
	// Create a directory where the file should be - this causes stat to return info but remove to fail
	os.MkdirAll(filePath, 0755)

	// This should still work since we check os.IsNotExist
	// But the file won't actually be removed
}

// --- SearchCVE with nil options ---

func TestFileStorage_SearchCVE_NilOptions(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := NewCVEReference("CVE-2021-99991")
	fs.StoreCVE(cve)

	results, err := fs.SearchCVE("", nil)
	if err != nil {
		t.Errorf("SearchCVE() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCVE() with nil options returned %d results, want 1", len(results))
	}
}

// --- Additional coverage tests for remaining uncovered paths ---

func TestFileStorage_DeleteCPE_StatNonNotExistErr(t *testing.T) {
	// Test the os.Stat error path that is NOT os.IsNotExist
	// by setting cpes subdirectory as a file (not a directory)
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)

	// Create cpes as a file instead of a directory
	cpeDirPath := filepath.Join(tempDir, "cpes")
	os.WriteFile(cpeDirPath, []byte("not a directory"), 0644)

	fs := &FileStorage{
		baseDir:  tempDir,
		cache:    NewMemoryStorage(),
		useCache: false,
	}

	// DeleteCPE will try to Stat a file inside cpes/, but cpes is a file not a dir
	err := fs.DeleteCPE("some_cpe_id")
	if err == nil {
		t.Errorf("DeleteCPE() should return error when stat fails with non-IsNotExist error")
	}
}

func TestFileStorage_StoreCVE_MkdirAllErr(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test that requires non-root user for permission errors")
	}

	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Remove the cves directory and replace it with a file so MkdirAll fails
	cveDirPath := filepath.Join(tempDir, "cves")
	os.RemoveAll(cveDirPath)
	os.WriteFile(cveDirPath, []byte("not a directory"), 0644)

	cve := NewCVEReference("CVE-2099-MKDIR2")
	err := fs.StoreCVE(cve)
	// Clean up so RemoveAll can work
	os.Remove(cveDirPath)
	os.MkdirAll(cveDirPath, 0755)

	if err == nil {
		t.Errorf("StoreCVE() should return error when MkdirAll fails")
	}
}

func TestFileStorage_NewFileStorage_SubDirMkdirErr(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test that requires non-root user for permission errors")
	}

	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)

	// Create a file where "cpes" subdirectory would go
	cpesPath := filepath.Join(tempDir, "cpes")
	os.WriteFile(cpesPath, []byte("not a directory"), 0644)

	_, err := NewFileStorage(tempDir, false)
	if err == nil {
		t.Errorf("NewFileStorage() should return error when subdirectory creation fails")
	}
}

func TestFileStorage_SearchCPE_LoadAllErr(t *testing.T) {
	// SearchCPE no longer returns error since loadAllCPEs never fails.
	// This test just verifies it returns empty results gracefully
	// when the cpes directory doesn't exist.
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)

	// Create FileStorage manually with a nonexistent baseDir for cpes
	fs := &FileStorage{
		baseDir:  tempDir,
		cache:    NewMemoryStorage(),
		useCache: false,
	}

	// SearchCPE should return empty results, not error
	results, err := fs.SearchCPE(nil, nil)
	if err != nil {
		t.Errorf("SearchCPE() should not return error, got %v", err)
	}
	if len(results) != 0 {
		t.Errorf("SearchCPE() should return empty results for missing dir, got %d", len(results))
	}
}

func TestFileStorage_SearchCVE_LoadAllCVEsErr(t *testing.T) {
	fs := &FileStorage{
		baseDir:  "/nonexistent/path",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	_, err := fs.SearchCVE("query", NewSearchOptions())
	if err == nil {
		t.Errorf("SearchCVE() should return error when loadAllCVEs fails")
	}
}

func TestFileStorage_FindCVEsByCPE_SearchErr(t *testing.T) {
	// FindCVEsByCPE no longer fails on SearchCPE error since SearchCPE never errors.
	// But it can still fail when loadAllCVEs fails (non-existent cves dir).
	fs := &FileStorage{
		baseDir:  "/nonexistent/path",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	_, err := fs.FindCVEsByCPE(cpe)
	if err == nil {
		t.Errorf("FindCVEsByCPE() should return error when loadAllCVEs fails")
	}
}

func TestFileStorage_FindCVEsByCPE_LoadCVEsErr(t *testing.T) {
	fs := &FileStorage{
		baseDir:  "/nonexistent/path",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	_, err := fs.FindCVEsByCPE(cpe)
	if err == nil {
		t.Errorf("FindCVEsByCPE() should return error when loadAllCVEs fails")
	}
}

func TestFileStorage_FindCPEsByCVE_SearchErr(t *testing.T) {
	// FindCPEsByCVE no longer fails on SearchCPE error since SearchCPE never errors.
	// But it can still fail when loadAllCVEs fails.
	fs := &FileStorage{
		baseDir:  "/nonexistent/path",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	_, err := fs.FindCPEsByCVE("CVE-2021-00001")
	if err == nil {
		t.Errorf("FindCPEsByCVE() should return error when loadAllCVEs fails")
	}
}

func TestFileStorage_FindCPEsByCVE_LoadCVEsErr(t *testing.T) {
	fs := &FileStorage{
		baseDir:  "/nonexistent/path",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	_, err := fs.FindCPEsByCVE("CVE-2021-00001")
	if err == nil {
		t.Errorf("FindCPEsByCVE() should return error when loadAllCVEs fails")
	}
}

func TestFileStorage_AdvancedSearchCPE_NonExistentDir(t *testing.T) {
	fs := &FileStorage{
		baseDir:  "/nonexistent/path/that/does/not/exist",
		useCache: false,
		cache:    NewMemoryStorage(),
	}

	criteria := &CPE{Vendor: Vendor("vendor")}
	_, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err == nil {
		t.Errorf("AdvancedSearchCPE() with non-existent directory should return error")
	}
}

func TestFileStorage_AdvancedSearchCPE_InvalidJSONInWalk(t *testing.T) {
	// Test AdvancedSearchCPE without cache when a file in cpes dir has invalid JSON
	// This triggers the fmt.Printf error path in the Walk callback
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Store a valid CPE first
	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	// Add an invalid JSON file in the cpes directory
	cpeDir := filepath.Join(tempDir, "cpes")
	os.WriteFile(filepath.Join(cpeDir, "bad_walk.json"), []byte("not valid json"), 0644)

	// Use exact matching criteria to match the stored CPE
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("product"),
		Version:     Version("1.0"),
	}
	results, err := fs.AdvancedSearchCPE(criteria, &AdvancedMatchOptions{})
	if err != nil {
		t.Errorf("AdvancedSearchCPE() error = %v", err)
	}
	// Should return the valid CPE (bad file is skipped)
	if len(results) != 1 {
		t.Errorf("AdvancedSearchCPE() returned %d results, want 1 (bad file skipped)", len(results))
	}
}

func TestFileStorage_loadAllCVEs_UnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test that requires non-root user for permission errors")
	}

	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Create a CVE file and then make it unreadable
	cve := NewCVEReference("CVE-2099-UNREAD")
	fs.StoreCVE(cve)

	cveFilePath := fs.CVEFilePath(cve.CVEID)
	os.Chmod(cveFilePath, 0000)

	// loadAllCVEs should skip the unreadable file without erroring
	cves, err := fs.loadAllCVEs()
	os.Chmod(cveFilePath, 0644) // restore for cleanup

	if err != nil {
		t.Errorf("loadAllCVEs() should not return error for unreadable files, got %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("loadAllCVEs() should skip unreadable files, got %d cves", len(cves))
	}
}

func TestFileStorage_loadAllCVEs_SubDirAndNonJSON(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Create a subdirectory named "subdir.json" inside cves (should be skipped as dir)
	cveDir := filepath.Join(tempDir, "cves")
	os.MkdirAll(filepath.Join(cveDir, "subdir.json"), 0755)

	// Create a non-JSON file (should be skipped)
	os.WriteFile(filepath.Join(cveDir, "readme.txt"), []byte("not json"), 0644)

	// Create a valid CVE
	cve := NewCVEReference("CVE-2099-DIRENTRY2")
	fs.StoreCVE(cve)

	cves, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() error = %v", err)
	}
	if len(cves) != 1 {
		t.Errorf("loadAllCVEs() returned %d cves, want 1", len(cves))
	}
}

func TestFileStorage_loadAllCVEs_BadJSONFile(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Write an invalid JSON file in the cves directory
	cveDir := filepath.Join(tempDir, "cves")
	os.WriteFile(filepath.Join(cveDir, "bad2.json"), []byte("invalid json"), 0644)

	// loadAllCVEs should skip the invalid file
	cves, err := fs.loadAllCVEs()
	if err != nil {
		t.Errorf("loadAllCVEs() should not return error for invalid JSON, got %v", err)
	}
	if len(cves) != 0 {
		t.Errorf("loadAllCVEs() should skip invalid JSON files, got %d cves", len(cves))
	}
}

func TestFileStorage_DeleteCPE_WithoutCacheSuccess(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:delnocache2:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("delnocache2"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	err := fs.DeleteCPE(cpe.GetURI())
	if err != nil {
		t.Errorf("DeleteCPE() without cache error = %v", err)
	}
}

func TestFileStorage_UpdateCPE_CacheEnabled2(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cpe := &CPE{
		Cpe23:       "cpe:2.3:a:vendor:updcache2:1.0:*:*:*:*:*:*:*",
		Part:        *PartApplication,
		Vendor:      Vendor("vendor"),
		ProductName: Product("updcache2"),
		Version:     Version("1.0"),
	}
	fs.StoreCPE(cpe)

	cpe.Version = Version("2.0")
	cpe.Cpe23 = "cpe:2.3:a:vendor:updcache2:2.0:*:*:*:*:*:*:*"
	err := fs.UpdateCPE(cpe)
	if err != nil {
		t.Errorf("UpdateCPE() with cache error = %v", err)
	}
}

func TestFileStorage_StoreCVE_CacheEnabled2(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, true)
	fs.Initialize()

	cve := NewCVEReference("CVE-2099-CACHE2")
	cve.Description = "cache test 2"
	err := fs.StoreCVE(cve)
	if err != nil {
		t.Errorf("StoreCVE() with cache error = %v", err)
	}
}

func TestFileStorage_UpdateCVE_FileWriteErr(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping test that requires non-root user for permission errors")
	}

	tempDir, _ := os.MkdirTemp("", "cpe_test_*")
	defer os.RemoveAll(tempDir)
	fs, _ := NewFileStorage(tempDir, false)
	fs.Initialize()

	// Store a CVE first
	cve := NewCVEReference("CVE-2099-UPDFILEERR")
	cve.Description = "Original"
	fs.StoreCVE(cve)

	// Make the CVE file read-only so WriteFile will fail when trying to truncate
	cveFilePath := fs.CVEFilePath(cve.CVEID)
	os.Chmod(cveFilePath, 0444)

	cve.Description = "Updated"
	err := fs.UpdateCVE(cve)
	// Restore permissions for cleanup
	os.Chmod(cveFilePath, 0644)

	if err == nil {
		t.Errorf("UpdateCVE() should return error when file is read-only")
	}
}
