package cpe

import (
	"errors"
	"time"
)

// 存储接口定义的错误
var (
	// ErrNotFound 表示记录不存在
	ErrNotFound = errors.New("record not found")

	// ErrDuplicate 表示记录已存在
	ErrDuplicate = errors.New("duplicate record")

	// ErrInvalidData 表示数据无效
	ErrInvalidData = errors.New("invalid data")

	// ErrStorageDisconnected 表示存储未连接
	ErrStorageDisconnected = errors.New("storage is disconnected")
)

// Storage 定义了CPE数据的存储接口
type Storage interface {
	// Initialize 初始化存储
	Initialize() error

	// Close 关闭存储连接
	Close() error

	// StoreCPE 存储单个CPE
	StoreCPE(cpe *CPE) error

	// RetrieveCPE 根据ID检索CPE
	RetrieveCPE(id string) (*CPE, error)

	// UpdateCPE 更新CPE
	UpdateCPE(cpe *CPE) error

	// DeleteCPE 删除CPE
	DeleteCPE(id string) error

	// SearchCPE 搜索CPE
	SearchCPE(criteria *CPE, options *MatchOptions) ([]*CPE, error)

	// AdvancedSearchCPE 高级搜索CPE
	AdvancedSearchCPE(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error)

	// StoreCVE 存储CVE信息
	StoreCVE(cve *CVEReference) error

	// RetrieveCVE 根据CVE ID检索CVE信息
	RetrieveCVE(cveID string) (*CVEReference, error)

	// UpdateCVE 更新CVE信息
	UpdateCVE(cve *CVEReference) error

	// DeleteCVE 删除CVE信息
	DeleteCVE(cveID string) error

	// SearchCVE 搜索CVE
	SearchCVE(query string, options *SearchOptions) ([]*CVEReference, error)

	// FindCVEsByCPE 查找与CPE关联的CVE
	FindCVEsByCPE(cpe *CPE) ([]*CVEReference, error)

	// FindCPEsByCVE 查找与CVE关联的CPE
	FindCPEsByCVE(cveID string) ([]*CPE, error)

	// StoreDictionary 存储CPE字典
	StoreDictionary(dict *CPEDictionary) error

	// RetrieveDictionary 检索CPE字典
	RetrieveDictionary() (*CPEDictionary, error)

	// StoreModificationTimestamp 存储最后修改时间
	StoreModificationTimestamp(key string, timestamp time.Time) error

	// RetrieveModificationTimestamp 检索最后修改时间
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
