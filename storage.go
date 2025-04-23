package cpe

import (
	"errors"
	"time"
)

/**
 * 存储接口定义的错误常量
 * 这些错误常量用于存储操作中可能遇到的常见错误情况，
 * 标准化了错误处理，便于使用者统一处理不同存储实现中的错误。
 */
var (
	// ErrNotFound 表示请求的记录在存储中不存在
	ErrNotFound = errors.New("record not found")

	// ErrDuplicate 表示尝试存储的记录已经存在（通常在主键冲突时）
	ErrDuplicate = errors.New("duplicate record")

	// ErrInvalidData 表示提供的数据无效或不符合存储要求
	ErrInvalidData = errors.New("invalid data")

	// ErrStorageDisconnected 表示存储后端未连接或连接已断开
	ErrStorageDisconnected = errors.New("storage is disconnected")
)

/**
 * Storage 定义了CPE和CVE数据的存储接口
 *
 * 该接口提供了一组统一的方法来存储、检索、更新和搜索CPE和CVE数据，
 * 使得不同的存储实现（如文件存储、内存存储、数据库存储等）能够以一致的方式使用。
 *
 * 示例:
 *   ```go
 *   // 创建文件存储
 *   storage, err := cpe.NewFileStorage("/path/to/storage", true)
 *   if err != nil {
 *       log.Fatalf("无法创建存储: %v", err)
 *   }
 *
 *   // 初始化存储
 *   if err := storage.Initialize(); err != nil {
 *       log.Fatalf("初始化存储失败: %v", err)
 *   }
 *
 *   // 存储CPE
 *   windowsCPE := &cpe.CPE{
 *       Cpe23:       "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *       Version:     cpe.Version("10"),
 *   }
 *   if err := storage.StoreCPE(windowsCPE); err != nil {
 *       log.Printf("存储CPE失败: %v", err)
 *   }
 *
 *   // 检索CPE
 *   retrievedCPE, err := storage.RetrieveCPE(windowsCPE.GetURI())
 *   if err != nil {
 *       if errors.Is(err, cpe.ErrNotFound) {
 *           log.Println("CPE不存在")
 *       } else {
 *           log.Printf("检索CPE失败: %v", err)
 *       }
 *   }
 *
 *   // 使用完毕后关闭存储
 *   defer storage.Close()
 *   ```
 */
type Storage interface {
	/**
	 * Initialize 初始化存储
	 *
	 * 该方法用于执行存储系统所需的初始化操作，如创建目录、建立连接、初始化表结构等。
	 * 在使用存储系统前应首先调用此方法。
	 *
	 * @return error 初始化过程中发生的错误，成功则返回nil
	 */
	Initialize() error

	/**
	 * Close 关闭存储连接
	 *
	 * 关闭与存储系统的连接，释放相关资源。使用完存储后应调用此方法。
	 *
	 * @return error 关闭过程中发生的错误，成功则返回nil
	 */
	Close() error

	/**
	 * StoreCPE 存储单个CPE对象
	 *
	 * 将CPE对象持久化到存储系统中。如果存储中已存在相同ID的CPE，
	 * 具体行为取决于实现（可能返回错误或覆盖现有记录）。
	 *
	 * @param cpe *CPE 要存储的CPE对象
	 * @return error 存储过程中发生的错误，成功则返回nil
	 */
	StoreCPE(cpe *CPE) error

	/**
	 * RetrieveCPE 根据ID检索CPE
	 *
	 * 从存储中检索指定ID的CPE对象。通常ID是CPE的URI表示形式。
	 *
	 * @param id string CPE的唯一标识符
	 * @return *CPE 检索到的CPE对象
	 * @return error 检索过程中发生的错误，如果未找到则返回ErrNotFound
	 */
	RetrieveCPE(id string) (*CPE, error)

	/**
	 * UpdateCPE 更新CPE
	 *
	 * 更新存储中已存在的CPE对象。如果指定ID的CPE不存在，则返回错误。
	 *
	 * @param cpe *CPE 包含更新信息的CPE对象
	 * @return error 更新过程中发生的错误，成功则返回nil
	 */
	UpdateCPE(cpe *CPE) error

	/**
	 * DeleteCPE 删除CPE
	 *
	 * 从存储中删除指定ID的CPE对象。
	 *
	 * @param id string 要删除的CPE的唯一标识符
	 * @return error 删除过程中发生的错误，成功则返回nil
	 */
	DeleteCPE(id string) error

	/**
	 * SearchCPE 搜索CPE
	 *
	 * 根据给定的条件和选项搜索匹配的CPE对象。
	 *
	 * @param criteria *CPE 搜索条件，包含要匹配的CPE属性
	 * @param options *MatchOptions 匹配选项，控制匹配行为
	 * @return []*CPE 匹配的CPE对象列表
	 * @return error 搜索过程中发生的错误，成功则返回nil
	 */
	SearchCPE(criteria *CPE, options *MatchOptions) ([]*CPE, error)

	/**
	 * AdvancedSearchCPE 高级搜索CPE
	 *
	 * 使用高级匹配选项搜索CPE对象，支持更复杂的匹配条件。
	 *
	 * @param criteria *CPE 搜索条件
	 * @param options *AdvancedMatchOptions 高级匹配选项
	 * @return []*CPE 匹配的CPE对象列表
	 * @return error 搜索过程中发生的错误，成功则返回nil
	 */
	AdvancedSearchCPE(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error)

	/**
	 * StoreCVE 存储CVE信息
	 *
	 * 将CVE引用对象持久化到存储系统中。
	 *
	 * @param cve *CVEReference 要存储的CVE引用对象
	 * @return error 存储过程中发生的错误，成功则返回nil
	 */
	StoreCVE(cve *CVEReference) error

	/**
	 * RetrieveCVE 根据CVE ID检索CVE信息
	 *
	 * 从存储中检索指定ID的CVE引用对象。
	 *
	 * @param cveID string CVE的唯一标识符，如"CVE-2021-44228"
	 * @return *CVEReference 检索到的CVE引用对象
	 * @return error 检索过程中发生的错误，如果未找到则返回ErrNotFound
	 */
	RetrieveCVE(cveID string) (*CVEReference, error)

	/**
	 * UpdateCVE 更新CVE信息
	 *
	 * 更新存储中已存在的CVE引用对象。
	 *
	 * @param cve *CVEReference 包含更新信息的CVE引用对象
	 * @return error 更新过程中发生的错误，成功则返回nil
	 */
	UpdateCVE(cve *CVEReference) error

	/**
	 * DeleteCVE 删除CVE信息
	 *
	 * 从存储中删除指定ID的CVE引用对象。
	 *
	 * @param cveID string 要删除的CVE的唯一标识符
	 * @return error 删除过程中发生的错误，成功则返回nil
	 */
	DeleteCVE(cveID string) error

	/**
	 * SearchCVE 搜索CVE
	 *
	 * 根据查询字符串和搜索选项搜索匹配的CVE引用对象。
	 *
	 * @param query string 搜索查询字符串
	 * @param options *SearchOptions 搜索选项
	 * @return []*CVEReference 匹配的CVE引用对象列表
	 * @return error 搜索过程中发生的错误，成功则返回nil
	 */
	SearchCVE(query string, options *SearchOptions) ([]*CVEReference, error)

	/**
	 * FindCVEsByCPE 查找与CPE关联的CVE
	 *
	 * 查找影响指定CPE的所有CVE引用对象。
	 *
	 * @param cpe *CPE 目标CPE对象
	 * @return []*CVEReference 与指定CPE关联的CVE引用对象列表
	 * @return error 查找过程中发生的错误，成功则返回nil
	 */
	FindCVEsByCPE(cpe *CPE) ([]*CVEReference, error)

	/**
	 * FindCPEsByCVE 查找与CVE关联的CPE
	 *
	 * 查找受指定CVE影响的所有CPE对象。
	 *
	 * @param cveID string CVE的唯一标识符
	 * @return []*CPE 与指定CVE关联的CPE对象列表
	 * @return error 查找过程中发生的错误，成功则返回nil
	 */
	FindCPEsByCVE(cveID string) ([]*CPE, error)

	/**
	 * StoreDictionary 存储CPE字典
	 *
	 * 将CPE字典对象持久化到存储系统中。
	 *
	 * @param dict *CPEDictionary 要存储的CPE字典对象
	 * @return error 存储过程中发生的错误，成功则返回nil
	 */
	StoreDictionary(dict *CPEDictionary) error

	/**
	 * RetrieveDictionary 检索CPE字典
	 *
	 * 从存储中检索CPE字典对象。
	 *
	 * @return *CPEDictionary 检索到的CPE字典对象
	 * @return error 检索过程中发生的错误，如果未找到则返回ErrNotFound
	 */
	RetrieveDictionary() (*CPEDictionary, error)

	/**
	 * StoreModificationTimestamp 存储最后修改时间
	 *
	 * 记录特定键的最后修改时间戳，用于跟踪数据更新。
	 *
	 * @param key string 时间戳的键
	 * @param timestamp time.Time 时间戳值
	 * @return error 存储过程中发生的错误，成功则返回nil
	 */
	StoreModificationTimestamp(key string, timestamp time.Time) error

	/**
	 * RetrieveModificationTimestamp 检索最后修改时间
	 *
	 * 检索特定键的最后修改时间戳。
	 *
	 * @param key string 时间戳的键
	 * @return time.Time 检索到的时间戳
	 * @return error 检索过程中发生的错误，如果未找到则返回ErrNotFound
	 */
	RetrieveModificationTimestamp(key string) (time.Time, error)
}

// SearchOptions 搜索选项
type SearchOptions struct {
	// 分页选项
	Offset int
	Limit  int

	// 排序字段
	SortBy string

	// 排序方向(true为升序，false为降序)
	SortAscending bool

	// 过滤条件
	Filters map[string]interface{}

	// 全文搜索查询
	FullTextQuery string

	// 是否包含已弃用的项
	IncludeDeprecated bool

	// 日期范围过滤
	DateStart *time.Time
	DateEnd   *time.Time

	// 最小CVSS评分
	MinCVSS float64

	// 最大CVSS评分
	MaxCVSS float64
}

// NewSearchOptions 创建默认搜索选项
func NewSearchOptions() *SearchOptions {
	return &SearchOptions{
		Offset:            0,
		Limit:             100,
		SortBy:            "id",
		SortAscending:     true,
		Filters:           make(map[string]interface{}),
		IncludeDeprecated: false,
	}
}

// StorageStats 存储统计信息
type StorageStats struct {
	// CPE总数
	TotalCPEs int

	// CVE总数
	TotalCVEs int

	// 字典项总数
	TotalDictionaryItems int

	// 存储占用空间（字节）
	StorageBytes int64

	// 上次更新时间
	LastUpdated time.Time
}

// StorageManager 存储管理器
type StorageManager struct {
	// 主存储
	Primary Storage

	// 缓存存储
	Cache Storage

	// 是否启用缓存
	CacheEnabled bool

	// 缓存有效期（秒）
	CacheTTLSeconds int
}

// NewStorageManager 创建存储管理器
func NewStorageManager(primary Storage) *StorageManager {
	return &StorageManager{
		Primary:         primary,
		CacheEnabled:    false,
		CacheTTLSeconds: 3600, // 默认1小时
	}
}

// SetCache 设置缓存存储
func (sm *StorageManager) SetCache(cache Storage) {
	sm.Cache = cache
	sm.CacheEnabled = true
}

// GetCPE 获取CPE，优先从缓存获取
func (sm *StorageManager) GetCPE(id string) (*CPE, error) {
	// 如果启用了缓存，先尝试从缓存获取
	if sm.CacheEnabled && sm.Cache != nil {
		cpe, err := sm.Cache.RetrieveCPE(id)
		if err == nil {
			return cpe, nil
		}
	}

	// 从主存储获取
	cpe, err := sm.Primary.RetrieveCPE(id)
	if err != nil {
		return nil, err
	}

	// 如果启用了缓存，将结果存入缓存
	if sm.CacheEnabled && sm.Cache != nil {
		_ = sm.Cache.StoreCPE(cpe) // 忽略缓存错误
	}

	return cpe, nil
}

// StoreCPE 存储CPE
func (sm *StorageManager) StoreCPE(cpe *CPE) error {
	// 保存到主存储
	err := sm.Primary.StoreCPE(cpe)
	if err != nil {
		return err
	}

	// 如果启用了缓存，也保存到缓存
	if sm.CacheEnabled && sm.Cache != nil {
		_ = sm.Cache.StoreCPE(cpe) // 忽略缓存错误
	}

	return nil
}

// GetCVE 获取CVE，优先从缓存获取
func (sm *StorageManager) GetCVE(cveID string) (*CVEReference, error) {
	// 如果启用了缓存，先尝试从缓存获取
	if sm.CacheEnabled && sm.Cache != nil {
		cve, err := sm.Cache.RetrieveCVE(cveID)
		if err == nil {
			return cve, nil
		}
	}

	// 从主存储获取
	cve, err := sm.Primary.RetrieveCVE(cveID)
	if err != nil {
		return nil, err
	}

	// 如果启用了缓存，将结果存入缓存
	if sm.CacheEnabled && sm.Cache != nil {
		_ = sm.Cache.StoreCVE(cve) // 忽略缓存错误
	}

	return cve, nil
}

// Search 搜索CPE
func (sm *StorageManager) Search(criteria *CPE, options *MatchOptions) ([]*CPE, error) {
	// 搜索不使用缓存，直接从主存储搜索
	return sm.Primary.SearchCPE(criteria, options)
}

// AdvancedSearch 高级搜索CPE
func (sm *StorageManager) AdvancedSearch(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error) {
	// 高级搜索不使用缓存，直接从主存储搜索
	return sm.Primary.AdvancedSearchCPE(criteria, options)
}

// InvalidateCache 使指定CPE的缓存失效
func (sm *StorageManager) InvalidateCache(id string) {
	if sm.CacheEnabled && sm.Cache != nil {
		_ = sm.Cache.DeleteCPE(id) // 忽略缓存错误
	}
}

// ClearCache 清空缓存
func (sm *StorageManager) ClearCache() error {
	if !sm.CacheEnabled || sm.Cache == nil {
		return nil
	}

	// 创建并初始化一个新的缓存实例来清空缓存
	err := sm.Cache.Initialize()
	if err != nil {
		return err
	}

	return nil
}

// GetStats 获取存储统计信息
func (sm *StorageManager) GetStats() (*StorageStats, error) {
	// 统计信息只从主存储获取

	// 这只是一个简单的实现示例，实际实现可能更复杂
	var stats StorageStats

	// 获取CPE总数
	cpes, err := sm.Primary.SearchCPE(nil, &MatchOptions{})
	if err != nil {
		return nil, err
	}
	stats.TotalCPEs = len(cpes)

	// 获取CVE总数
	cves, err := sm.Primary.SearchCVE("", NewSearchOptions())
	if err != nil {
		return nil, err
	}
	stats.TotalCVEs = len(cves)

	// 获取字典信息
	dict, err := sm.Primary.RetrieveDictionary()
	if err == nil && dict != nil {
		stats.TotalDictionaryItems = len(dict.Items)
	}

	// 获取最后更新时间
	lastUpdated, err := sm.Primary.RetrieveModificationTimestamp("last_update")
	if err == nil {
		stats.LastUpdated = lastUpdated
	} else {
		stats.LastUpdated = time.Now()
	}

	return &stats, nil
}
