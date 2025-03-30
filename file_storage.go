package cpe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// FileStorage 是一个基于文件系统的存储实现
type FileStorage struct {
	// 基础目录，用于存储所有数据
	baseDir string

	// 缓存存储，用于提高读取性能
	cache *MemoryStorage

	// 使用缓存
	useCache bool

	// 用于保护文件操作的互斥锁
	mutex sync.RWMutex
}

/**
 * NewFileStorage 创建基于文件系统的CPE数据存储实例
 *
 * 此函数会在指定的基础目录下创建必要的子目录结构，包括cpes、cves、dictionary和metadata文件夹，
 * 用于存储不同类型的数据。还可以选择是否启用内存缓存以提高性能。
 *
 * @param baseDir 存储数据的基础目录路径，如果不存在会自动创建
 * @param useCache 是否使用内存缓存来提高读取性能
 * @return (*FileStorage, error) 成功时返回FileStorage实例指针，失败时返回nil和错误
 *
 * @error 当无法创建基础目录或子目录时，返回错误
 * @error 当启用缓存但无法初始化缓存时，返回错误
 *
 * 示例:
 *   ```go
 *   // 创建临时目录用于存储CPE数据
 *   tempDir, err := os.MkdirTemp("", "cpe-storage-*")
 *   if err != nil {
 *       log.Fatalf("创建临时目录失败: %v", err)
 *   }
 *   defer os.RemoveAll(tempDir) // 在程序结束时清理
 *
 *   // 创建带缓存的文件存储
 *   storage, err := cpe.NewFileStorage(tempDir, true)
 *   if err != nil {
 *       log.Fatalf("创建存储失败: %v", err)
 *   }
 *   defer storage.Close() // 确保资源正确释放
 *
 *   // 现在可以使用storage进行CPE的存储和检索操作
 *   ```
 */
func NewFileStorage(baseDir string, useCache bool) (*FileStorage, error) {
	// 确保基础目录存在
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	// 创建子目录
	subDirs := []string{"cpes", "cves", "dictionary", "metadata"}
	for _, dir := range subDirs {
		path := filepath.Join(baseDir, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create %s directory: %w", dir, err)
		}
	}

	fs := &FileStorage{
		baseDir:  baseDir,
		cache:    NewMemoryStorage(),
		useCache: useCache,
		mutex:    sync.RWMutex{},
	}

	// 如果使用缓存，初始化缓存
	if useCache {
		if err := fs.cache.Initialize(); err != nil {
			return nil, fmt.Errorf("failed to initialize cache: %w", err)
		}
	}

	return fs, nil
}

// Initialize 初始化存储
func (fs *FileStorage) Initialize() error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 如果使用缓存，初始化缓存
	if fs.useCache {
		if err := fs.cache.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize cache: %w", err)
		}
	}

	// 记录初始化时间
	return fs.StoreModificationTimestamp("initialization", time.Now())
}

// Close 关闭存储连接
func (fs *FileStorage) Close() error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 如果使用缓存，关闭缓存
	if fs.useCache {
		if err := fs.cache.Close(); err != nil {
			return fmt.Errorf("failed to close cache: %w", err)
		}
	}

	return nil
}

// CPEFilePath 根据CPE ID获取CPE文件路径
func (fs *FileStorage) CPEFilePath(id string) string {
	// 使用CPE ID的哈希作为文件名，以避免文件名过长或包含无效字符
	hash := hashString(id)
	return filepath.Join(fs.baseDir, "cpes", hash+".json")
}

// CVEFilePath 根据CVE ID获取CVE文件路径
func (fs *FileStorage) CVEFilePath(id string) string {
	// 使用CVE ID作为文件名
	sanitizedID := sanitizeFileName(id)
	return filepath.Join(fs.baseDir, "cves", sanitizedID+".json")
}

// DictionaryFilePath 获取字典文件路径
func (fs *FileStorage) DictionaryFilePath() string {
	return filepath.Join(fs.baseDir, "dictionary", "cpe_dictionary.json")
}

// MetadataFilePath 根据键获取元数据文件路径
func (fs *FileStorage) MetadataFilePath(key string) string {
	sanitizedKey := sanitizeFileName(key)
	return filepath.Join(fs.baseDir, "metadata", sanitizedKey+".json")
}

// StoreCPE 存储单个CPE
func (fs *FileStorage) StoreCPE(cpe *CPE) error {
	if cpe == nil {
		return ErrInvalidData
	}

	// 确保CPE有ID
	if cpe.GetURI() == "" {
		return fmt.Errorf("CPE must have a URI: %w", ErrInvalidData)
	}

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 序列化CPE为JSON
	data, err := json.MarshalIndent(cpe, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CPE: %w", err)
	}

	// 写入文件
	filePath := fs.CPEFilePath(cpe.GetURI())
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CPE file: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.StoreCPE(cpe); err != nil {
			return fmt.Errorf("failed to update cache: %w", err)
		}
	}

	// 更新时间戳
	return fs.StoreModificationTimestamp("last_cpe_update", time.Now())
}

/**
 * RetrieveCPE 根据CPE URI检索CPE对象
 *
 * 此方法首先尝试从内存缓存（如果启用）中获取CPE，缓存未命中时则从文件系统读取CPE数据。
 * 检索到的CPE会被添加到缓存中（如果启用缓存）以加速后续访问。
 *
 * @param id CPE URI，作为检索CPE的唯一标识符，如"cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
 * @return (*CPE, error) 成功时返回检索到的CPE结构体指针，失败时返回nil和错误
 *
 * @error 当CPE不存在时，返回ErrNotFound
 * @error 当无法读取文件或解析JSON数据时，返回相应错误
 *
 * 示例:
 *   ```go
 *   // 以Windows 10的CPE URI为例
 *   cpeURI := "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
 *
 *   // 从存储中检索CPE
 *   winCPE, err := storage.RetrieveCPE(cpeURI)
 *   if err != nil {
 *       if err == cpe.ErrNotFound {
 *           log.Printf("CPE不存在: %s", cpeURI)
 *       } else {
 *           log.Fatalf("检索CPE失败: %v", err)
 *       }
 *   } else {
 *       fmt.Printf("成功检索到CPE: %s (厂商: %s, 产品: %s)\n",
 *                  cpeURI, winCPE.Vendor, winCPE.ProductName)
 *   }
 *   ```
 */
func (fs *FileStorage) RetrieveCPE(id string) (*CPE, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// 如果使用缓存，先尝试从缓存获取
	if fs.useCache {
		cpe, err := fs.cache.RetrieveCPE(id)
		if err == nil {
			return cpe, nil
		}
	}

	// 从文件读取
	filePath := fs.CPEFilePath(id)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read CPE file: %w", err)
	}

	// 反序列化JSON为CPE
	var cpe CPE
	if err := json.Unmarshal(data, &cpe); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CPE: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		_ = fs.cache.StoreCPE(&cpe) // 忽略缓存错误
	}

	return &cpe, nil
}

// UpdateCPE 更新一个CPE记录
func (f *FileStorage) UpdateCPE(cpe *CPE) error {
	if cpe == nil {
		return ErrInvalidData
	}

	// 确保CPE有ID
	if cpe.GetURI() == "" {
		return fmt.Errorf("CPE must have a URI: %w", ErrInvalidData)
	}

	// 简单地存储新的CPE, 不尝试寻找和删除旧版本
	if err := f.StoreCPE(cpe); err != nil {
		return err
	}

	// 如果使用缓存，更新缓存
	if f.useCache {
		if err := f.cache.UpdateCPE(cpe); err != nil {
			fmt.Printf("Failed to update CPE in cache: %v", err)
		}
	}

	return nil
}

// DeleteCPE 删除一个CPE记录
func (f *FileStorage) DeleteCPE(uri string) error {
	if f.useCache {
		// 从缓存中删除
		err := f.cache.DeleteCPE(uri)
		if err != nil {
			// 即使缓存删除失败，我们仍然尝试删除文件
			// 但这可能表示缓存和文件不同步
			fmt.Printf("Failed to delete CPE from cache: %v", err)
		}
	}

	// 获取文件路径
	filePath := f.CPEFilePath(uri)

	// 检查文件是否存在
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，忽略这个错误
			return nil
		}
		return err
	}

	// 删除文件
	return os.Remove(filePath)
}

/**
 * SearchCPE 根据条件搜索CPE记录
 *
 * 此方法允许根据指定的查询条件和选项搜索CPE数据库。
 * 可以搜索CPE的各种属性，如供应商名称、产品名称或版本号。
 *
 * @param criteria *CPE 搜索条件，包含要匹配的CPE字段，如果为nil则返回所有CPE
 * @param options *MatchOptions 匹配选项，控制匹配行为，如忽略版本或使用正则表达式
 * @return ([]*CPE, error) 成功时返回匹配的CPE列表，失败时返回nil和错误
 *
 * @error 当读取目录或文件失败时，返回相应错误
 * @error 当解析CPE数据失败时，返回相应错误
 *
 * 示例:
 *   ```go
 *   // 搜索所有Microsoft的产品
 *   criteria := &cpe.CPE{
 *       Vendor: cpe.Vendor("microsoft"),
 *   }
 *
 *   // 设置匹配选项，忽略版本匹配
 *   options := &cpe.MatchOptions{
 *       IgnoreVersion: true,
 *   }
 *
 *   // 执行搜索
 *   results, err := storage.SearchCPE(criteria, options)
 *   if err != nil {
 *       log.Fatalf("搜索CPE失败: %v", err)
 *   }
 *
 *   // 显示搜索结果
 *   fmt.Printf("找到 %d 个匹配的CPE:\n", len(results))
 *   for i, cpeItem := range results {
 *       fmt.Printf("%d. %s (产品: %s, 版本: %s)\n",
 *                 i+1, cpeItem.GetURI(), cpeItem.ProductName, cpeItem.Version)
 *   }
 *
 *   // 搜索所有CPE
 *   allCPEs, err := storage.SearchCPE(nil, nil)
 *   if err != nil {
 *       log.Fatalf("获取所有CPE失败: %v", err)
 *   }
 *   fmt.Printf("总共有 %d 个CPE记录\n", len(allCPEs))
 *   ```
 */
func (f *FileStorage) SearchCPE(criteria *CPE, options *MatchOptions) ([]*CPE, error) {
	// 首先加载所有CPE
	allCPEs, err := f.loadAllCPEs()
	if err != nil {
		return nil, fmt.Errorf("failed to load CPEs: %w", err)
	}

	// 如果没有查询条件，返回所有CPE
	if criteria == nil {
		return allCPEs, nil
	}

	// 使用Search函数进行匹配
	return Search(allCPEs, criteria, options), nil
}

// 加载所有CPE记录
func (f *FileStorage) loadAllCPEs() ([]*CPE, error) {
	cpeDir := filepath.Join(f.baseDir, "cpes")

	// 检查目录是否存在
	if _, err := os.Stat(cpeDir); os.IsNotExist(err) {
		return []*CPE{}, nil
	}

	// 获取所有JSON文件
	files, err := filepath.Glob(filepath.Join(cpeDir, "*.json"))
	if err != nil {
		return nil, err
	}

	var cpes []*CPE

	// 读取每个文件
	for _, file := range files {
		cpe, err := f.readCPEFromFile(file)
		if err != nil {
			// 记录错误但继续处理
			fmt.Printf("Error reading CPE from %s: %v\n", file, err)
			continue
		}
		cpes = append(cpes, cpe)
	}

	return cpes, nil
}

// 从文件中读取CPE
func (f *FileStorage) readCPEFromFile(filePath string) (*CPE, error) {
	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// 解析JSON
	var cpe CPE
	err = json.Unmarshal(data, &cpe)
	if err != nil {
		return nil, err
	}

	return &cpe, nil
}

// StoreCVE 存储CVE
func (fs *FileStorage) StoreCVE(cve *CVEReference) error {
	if cve == nil {
		return ErrInvalidData
	}

	// 确保CVE有ID
	if cve.CVEID == "" {
		return fmt.Errorf("CVE must have an ID: %w", ErrInvalidData)
	}

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 检查文件夹是否存在
	cveDir := filepath.Join(fs.baseDir, "cves")
	if err := os.MkdirAll(cveDir, 0755); err != nil {
		return fmt.Errorf("failed to create CVE directory: %w", err)
	}

	// 构建文件路径
	filePath := fs.CVEFilePath(cve.CVEID)

	// 序列化CVE为JSON
	data, err := json.MarshalIndent(cve, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CVE: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CVE file: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.StoreCVE(cve); err != nil {
			return fmt.Errorf("failed to update cache: %w", err)
		}
	}

	// 更新时间戳
	return fs.StoreModificationTimestamp("last_cve_update", time.Now())
}

// RetrieveCVE 查询CVE
func (fs *FileStorage) RetrieveCVE(cveID string) (*CVEReference, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// 如果使用缓存，先从缓存中查询
	if fs.useCache {
		cve, err := fs.cache.RetrieveCVE(cveID)
		// 如果缓存中有，或者出现了除"未找到"之外的错误，直接返回结果
		if err == nil || err != ErrNotFound {
			return cve, err
		}
		// 如果缓存中没有，继续从文件系统中查找
	}

	filePath := fs.CVEFilePath(cveID)

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, ErrNotFound
	}

	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CVE file: %w", err)
	}

	// 解析JSON
	var cve CVEReference
	if err := json.Unmarshal(data, &cve); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CVE: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.StoreCVE(&cve); err != nil {
			return nil, fmt.Errorf("failed to update cache: %w", err)
		}
	}

	return &cve, nil
}

// UpdateCVE 更新CVE信息
func (fs *FileStorage) UpdateCVE(cve *CVEReference) error {
	if cve == nil {
		return ErrInvalidData
	}

	// 确保CVE有ID
	if cve.CVEID == "" {
		return fmt.Errorf("CVE must have an ID: %w", ErrInvalidData)
	}

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 检查CVE是否存在
	filePath := fs.CVEFilePath(cve.CVEID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ErrNotFound
	}

	// 序列化CVE为JSON
	data, err := json.MarshalIndent(cve, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CVE: %w", err)
	}

	// 写入文件
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write CVE file: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.UpdateCVE(cve); err != nil {
			return fmt.Errorf("failed to update cache: %w", err)
		}
	}

	// 更新时间戳
	return fs.StoreModificationTimestamp("last_cve_update", time.Now())
}

// DeleteCVE 删除CVE信息
func (fs *FileStorage) DeleteCVE(cveID string) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 检查CVE是否存在
	filePath := fs.CVEFilePath(cveID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return ErrNotFound
	}

	// 删除文件
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete CVE file: %w", err)
	}

	// 如果使用缓存，从缓存中删除
	if fs.useCache {
		if err := fs.cache.DeleteCVE(cveID); err != nil {
			return fmt.Errorf("failed to delete from cache: %w", err)
		}
	}

	// 更新时间戳
	return fs.StoreModificationTimestamp("last_cve_update", time.Now())
}

// SearchCVE 搜索CVE
func (fs *FileStorage) SearchCVE(query string, options *SearchOptions) ([]*CVEReference, error) {
	// 使用内存存储的搜索功能需要先加载所有CVE到内存
	allCVEs, err := fs.loadAllCVEs()
	if err != nil {
		return nil, err
	}

	// 使用内存存储执行搜索
	tempStorage := NewMemoryStorage()
	for _, cve := range allCVEs {
		_ = tempStorage.StoreCVE(cve)
	}

	return tempStorage.SearchCVE(query, options)
}

// loadAllCVEs 加载所有CVE
func (fs *FileStorage) loadAllCVEs() ([]*CVEReference, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// 如果使用缓存且缓存已加载，直接从缓存获取
	if fs.useCache {
		return fs.cache.SearchCVE("", nil)
	}

	// 获取CVE目录中的所有文件
	cveDir := filepath.Join(fs.baseDir, "cves")
	files, err := os.ReadDir(cveDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read CVE directory: %w", err)
	}

	var cves []*CVEReference

	// 读取每个文件
	for _, file := range files {
		if file.IsDir() || !isJSONFile(file.Name()) {
			continue
		}

		filePath := filepath.Join(cveDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue // 忽略无法读取的文件
		}

		var cve CVEReference
		if err := json.Unmarshal(data, &cve); err != nil {
			continue // 忽略无法解析的文件
		}

		cves = append(cves, &cve)
	}

	return cves, nil
}

// FindCVEsByCPE 查找与CPE关联的CVE
func (fs *FileStorage) FindCVEsByCPE(cpe *CPE) ([]*CVEReference, error) {
	// 获取所有CPE和CVE
	allCPEs, err := fs.SearchCPE(nil, nil)
	if err != nil {
		return nil, err
	}

	allCVEs, err := fs.loadAllCVEs()
	if err != nil {
		return nil, err
	}

	// 使用内存存储执行搜索
	tempStorage := NewMemoryStorage()
	for _, c := range allCPEs {
		_ = tempStorage.StoreCPE(c)
	}
	for _, c := range allCVEs {
		_ = tempStorage.StoreCVE(c)
	}

	return tempStorage.FindCVEsByCPE(cpe)
}

// FindCPEsByCVE 查找与CVE关联的CPE
func (fs *FileStorage) FindCPEsByCVE(cveID string) ([]*CPE, error) {
	// 获取所有CPE和CVE
	allCPEs, err := fs.SearchCPE(nil, nil)
	if err != nil {
		return nil, err
	}

	allCVEs, err := fs.loadAllCVEs()
	if err != nil {
		return nil, err
	}

	// 使用内存存储执行搜索
	tempStorage := NewMemoryStorage()
	for _, c := range allCPEs {
		_ = tempStorage.StoreCPE(c)
	}
	for _, c := range allCVEs {
		_ = tempStorage.StoreCVE(c)
	}

	return tempStorage.FindCPEsByCVE(cveID)
}

/**
 * StoreDictionary 存储CPE字典
 *
 * 此方法将整个CPE字典序列化为JSON并存储到文件系统中。如果启用了缓存，
 * 也会同时更新内存缓存。还会更新字典的最后修改时间戳。
 *
 * @param dict 要存储的CPE字典，包含一组CPE项和元数据
 * @return error 成功时返回nil，失败时返回错误
 *
 * @error 当参数为nil时，返回ErrInvalidData
 * @error 当序列化字典失败时，返回错误
 * @error 当写入文件失败时，返回错误
 * @error 当更新缓存失败时，返回错误
 *
 * 示例:
 *   ```go
 *   // 创建一个新的CPE字典
 *   dictionary := &cpe.CPEDictionary{
 *       GeneratedAt:    time.Now(),
 *       SchemaVersion:  "2.3",
 *       Items:          make([]*cpe.CPEItem, 0),
 *   }
 *
 *   // 添加CPE项到字典
 *   windowsCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *
 *   // 创建Windows 10的字典项
 *   windowsItem := &cpe.CPEItem{
 *       Name:        windowsCPE.Cpe23,
 *       Title:       "Microsoft Windows 10",
 *       CPE:         windowsCPE,
 *       References:  []cpe.Reference{
 *           {
 *               URL:  "https://www.microsoft.com/windows",
 *               Type: "vendor",
 *           },
 *       },
 *   }
 *
 *   // 添加到字典
 *   dictionary.Items = append(dictionary.Items, windowsItem)
 *
 *   // 存储字典
 *   err := storage.StoreDictionary(dictionary)
 *   if err != nil {
 *       log.Fatalf("存储CPE字典失败: %v", err)
 *   }
 *
 *   fmt.Printf("成功存储包含 %d 条CPE记录的字典\n", len(dictionary.Items))
 *   ```
 */
func (fs *FileStorage) StoreDictionary(dict *CPEDictionary) error {
	if dict == nil {
		return ErrInvalidData
	}

	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	// 序列化字典为JSON
	data, err := json.MarshalIndent(dict, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dictionary: %w", err)
	}

	// 写入文件
	filePath := fs.DictionaryFilePath()
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write dictionary file: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.StoreDictionary(dict); err != nil {
			return fmt.Errorf("failed to update cache: %w", err)
		}
	}

	// 更新时间戳
	return fs.StoreModificationTimestamp("last_dictionary_update", time.Now())
}

// RetrieveDictionary 检索CPE字典
func (fs *FileStorage) RetrieveDictionary() (*CPEDictionary, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// 如果使用缓存，先尝试从缓存获取
	if fs.useCache {
		dict, err := fs.cache.RetrieveDictionary()
		if err == nil {
			return dict, nil
		}
	}

	// 从文件读取
	filePath := fs.DictionaryFilePath()
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read dictionary file: %w", err)
	}

	// 反序列化JSON为字典
	var dict CPEDictionary
	if err := json.Unmarshal(data, &dict); err != nil {
		return nil, fmt.Errorf("failed to unmarshal dictionary: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		_ = fs.cache.StoreDictionary(&dict) // 忽略缓存错误
	}

	return &dict, nil
}

// StoreModificationTimestamp 存储最后修改时间
func (fs *FileStorage) StoreModificationTimestamp(key string, timestamp time.Time) error {
	// 构造元数据对象
	metadata := struct {
		Key       string    `json:"key"`
		Timestamp time.Time `json:"timestamp"`
	}{
		Key:       key,
		Timestamp: timestamp,
	}

	// 序列化为JSON
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal timestamp metadata: %w", err)
	}

	// 写入文件
	filePath := fs.MetadataFilePath(key)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write timestamp metadata file: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		if err := fs.cache.StoreModificationTimestamp(key, timestamp); err != nil {
			return fmt.Errorf("failed to update cache: %w", err)
		}
	}

	return nil
}

// RetrieveModificationTimestamp 检索最后修改时间
func (fs *FileStorage) RetrieveModificationTimestamp(key string) (time.Time, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	// 如果使用缓存，先尝试从缓存获取
	if fs.useCache {
		timestamp, err := fs.cache.RetrieveModificationTimestamp(key)
		if err == nil {
			return timestamp, nil
		}
	}

	// 从文件读取
	filePath := fs.MetadataFilePath(key)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, ErrNotFound
		}
		return time.Time{}, fmt.Errorf("failed to read timestamp metadata file: %w", err)
	}

	// 反序列化JSON为元数据
	var metadata struct {
		Key       string    `json:"key"`
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal timestamp metadata: %w", err)
	}

	// 如果使用缓存，更新缓存
	if fs.useCache {
		_ = fs.cache.StoreModificationTimestamp(key, metadata.Timestamp) // 忽略缓存错误
	}

	return metadata.Timestamp, nil
}

// Helper functions

// hashString 计算字符串的简单哈希值，用作文件名
func hashString(s string) string {
	h := 0
	for i := 0; i < len(s); i++ {
		h = 31*h + int(s[i])
	}
	return fmt.Sprintf("%x", h)
}

// sanitizeFileName 清理文件名，移除不安全字符
func sanitizeFileName(name string) string {
	// 替换不安全字符为下划线
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	result := name
	for _, char := range unsafe {
		result = strings.ReplaceAll(result, char, "_")
	}
	return result
}

// isJSONFile 检查文件名是否为JSON文件
func isJSONFile(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".json")
}

// AdvancedSearchCPE 高级搜索CPE
func (f *FileStorage) AdvancedSearchCPE(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error) {
	// 如果使用缓存，从缓存中搜索
	if f.useCache {
		allCPEs, err := f.cache.SearchCPE(nil, nil)
		if err != nil {
			return nil, err
		}

		var results []*CPE
		for _, cpe := range allCPEs {
			if AdvancedMatchCPE(criteria, cpe, options) {
				cpeCopy := *cpe
				results = append(results, &cpeCopy)
			}
		}

		return results, nil
	}

	// 如果没有缓存，需要遍历目录
	var results []*CPE

	// 获取CPE目录
	cpeDir := filepath.Join(f.baseDir, "cpes")

	// 递归遍历所有JSON文件
	err := filepath.Walk(cpeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 只处理JSON文件
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".json") {
			// 读取文件内容
			cpe, err := f.readCPEFromFile(path)
			if err != nil {
				fmt.Printf("Error reading CPE file %s: %v", path, err)
				return nil // 继续处理下一个文件
			}

			// 匹配条件
			if AdvancedMatchCPE(criteria, cpe, options) {
				results = append(results, cpe)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}
