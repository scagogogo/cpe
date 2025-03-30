package cpe

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
