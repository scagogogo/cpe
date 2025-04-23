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
//
// 功能描述:
//   - 创建并初始化带有默认值的SearchOptions对象
//   - 提供搜索操作的基础配置，包括分页、排序和过滤设置
//   - 适用于需要搜索CPE或CVE数据时简化选项创建的场景
//
// 参数:
//   - 无
//
// 返回值:
//   - *SearchOptions: 初始化后的搜索选项对象，包含以下默认值:
//   - Offset: 0 (从第一条记录开始)
//   - Limit: 100 (每页最多返回100条记录)
//   - SortBy: "id" (默认按ID字段排序)
//   - SortAscending: true (默认升序排列)
//   - Filters: 空map (默认无过滤条件)
//   - IncludeDeprecated: false (默认不包含已弃用项)
//
// 使用示例:
//
//	// 创建默认搜索选项
//	options := cpe.NewSearchOptions()
//
//	// 修改默认值以满足特定需求
//	options.Limit = 50
//	options.SortBy = "severity"
//	options.SortAscending = false
//	options.Filters["vendor"] = "microsoft"
//
//	// 使用选项进行搜索
//	results, err := storage.SearchCVE("windows", options)
//
// 线程安全:
//   - 此函数是无状态的，可以在并发环境中安全调用
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
//
// 功能描述:
//   - 创建并初始化StorageManager对象，用于管理CPE和CVE数据的存储操作
//   - 支持主存储与缓存存储的分层架构，提高数据访问效率
//   - 管理器会自动处理主存储和缓存存储之间的数据同步
//
// 参数:
//   - primary Storage: 主存储接口实现，不能为nil，作为数据的持久化存储
//
// 返回值:
//   - *StorageManager: 初始化后的存储管理器对象，包含以下默认设置:
//   - Primary: 设置为传入的主存储
//   - Cache: nil (默认不启用缓存)
//   - CacheEnabled: false (默认缓存功能关闭)
//   - CacheTTLSeconds: 3600 (默认缓存有效期为1小时)
//
// 异常处理:
//   - 如果primary参数为nil，虽然函数不会立即返回错误，但在之后使用时会导致空指针异常
//
// 使用示例:
//
//	// 创建文件存储作为主存储
//	fileStorage, err := cpe.NewFileStorage("/path/to/data", true)
//	if err != nil {
//	    log.Fatalf("创建文件存储失败: %v", err)
//	}
//
//	// 初始化主存储
//	if err := fileStorage.Initialize(); err != nil {
//	    log.Fatalf("初始化存储失败: %v", err)
//	}
//
//	// 创建存储管理器
//	manager := cpe.NewStorageManager(fileStorage)
//
//	// 可选: 添加内存缓存以提高性能
//	memCache, _ := cpe.NewMemoryStorage()
//	memCache.Initialize()
//	manager.SetCache(memCache)
//
// 性能考虑:
//   - 添加缓存可以显著提高频繁访问相同数据时的性能
//   - 默认的缓存过期时间(1小时)适用于大多数场景，对于频繁更新的数据可能需要调整
//
// 线程安全:
//   - StorageManager本身的初始化是线程安全的
//   - 实际使用的线程安全性取决于传入的Storage实现
//
// 关联方法:
//   - SetCache: 设置缓存存储
//   - GetCPE, StoreCPE: CPE数据的获取与存储
func NewStorageManager(primary Storage) *StorageManager {
	return &StorageManager{
		Primary:         primary,
		CacheEnabled:    false,
		CacheTTLSeconds: 3600, // 默认1小时
	}
}

// SetCache 设置缓存存储
//
// 功能描述:
//   - 为存储管理器配置缓存存储，启用缓存功能
//   - 设置缓存后，管理器会在读取数据时优先从缓存获取，写入数据时同时更新缓存
//   - 提高频繁访问相同数据时的性能，减轻主存储负担
//
// 参数:
//   - cache Storage: 实现Storage接口的缓存存储对象，通常为内存存储
//   - 如果传入nil，缓存仍会被标记为启用，但实际不会生效(建议避免传入nil)
//
// 返回值:
//   - 无
//
// 副作用:
//   - 修改管理器的Cache属性为传入的缓存存储
//   - 将CacheEnabled设置为true，启用缓存功能
//
// 使用示例:
//
//	// 创建存储管理器
//	manager := cpe.NewStorageManager(primaryStorage)
//
//	// 创建内存缓存
//	memCache, _ := cpe.NewMemoryStorage()
//	memCache.Initialize()
//
//	// 设置缓存
//	manager.SetCache(memCache)
//
//	// 现在管理器会使用缓存来提高性能
//	cpe, err := manager.GetCPE("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")
//
// 注意事项:
//   - 在调用此方法前，应确保缓存存储已经正确初始化
//   - 此方法不会自动同步现有数据到缓存中，缓存会在后续访问时逐渐填充
//
// 关联方法:
//   - GetCPE, GetCVE: 会优先从缓存获取数据
//   - StoreCPE: 会同时更新缓存
//   - InvalidateCache, ClearCache: 用于管理缓存内容
func (sm *StorageManager) SetCache(cache Storage) {
	sm.Cache = cache
	sm.CacheEnabled = true
}

// GetCPE 获取CPE对象，优先从缓存获取
//
// 功能描述:
//   - 根据CPE ID检索对应的CPE对象
//   - 实现了两级存储查询策略: 如果缓存启用，优先从缓存查询，缓存未命中则从主存储查询
//   - 从主存储获取的数据会自动同步到缓存中，以便后续查询更快速
//
// 参数:
//   - id string: CPE的唯一标识符，通常为CPE 2.3格式的URI字符串
//   - 例如: "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*"
//   - 不能为空，否则可能导致未定义行为
//
// 返回值:
//   - *CPE: 成功检索到的CPE对象指针
//   - error: 如果检索失败则返回错误
//   - 可能的错误类型包括:
//   - ErrNotFound: 指定ID的CPE不存在
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 缓存行为:
//   - 如果缓存启用且缓存命中，直接返回缓存中的对象，不访问主存储
//   - 如果缓存启用但缓存未命中，从主存储获取并自动更新缓存
//   - 如果缓存未启用，或Cache为nil，直接从主存储获取
//
// 错误处理:
//   - 仅在主存储查询失败时返回错误，缓存查询失败会静默处理并继续查询主存储
//   - 将数据写入缓存失败不会影响返回结果，错误会被忽略
//
// 使用示例:
//
//	// 创建带缓存的存储管理器
//	manager := cpe.NewStorageManager(primaryStorage)
//	manager.SetCache(memoryCache)
//
//	// 获取Windows 10的CPE信息
//	windowsCPE, err := manager.GetCPE("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")
//	if err != nil {
//	    if errors.Is(err, cpe.ErrNotFound) {
//	        fmt.Println("CPE不存在")
//	    } else {
//	        fmt.Printf("获取CPE失败: %v\n", err)
//	    }
//	    return
//	}
//
//	// 使用获取到的CPE对象
//	fmt.Printf("产品名称: %s\n", windowsCPE.ProductName)
//
// 性能考虑:
//   - 缓存命中时，性能显著优于直接从主存储查询
//   - 频繁查询相同CPE时，建议启用缓存
//
// 关联方法:
//   - StoreCPE: 存储CPE并更新缓存
//   - InvalidateCache: 使指定CPE的缓存失效
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

// StoreCPE 存储CPE对象到主存储和缓存中
//
// 功能描述:
//   - 将CPE对象持久化保存到主存储中
//   - 如果缓存已启用，同时更新缓存中的对应数据
//   - 确保主存储和缓存的数据一致性
//
// 参数:
//   - cpe *CPE: 要存储的CPE对象指针，不能为nil
//   - 对象必须包含有效的识别信息(如Cpe23字段)以便正确存储
//   - 建议在存储前使用ValidateCPE验证对象有效性
//
// 返回值:
//   - error: 如果存储过程中发生错误则返回具体错误
//   - 可能的错误类型包括:
//   - ErrInvalidData: CPE数据无效
//   - ErrDuplicate: 已存在相同ID的CPE(取决于具体存储实现)
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 缓存行为:
//   - 如果缓存启用且Cache不为nil，成功写入主存储后会同步更新缓存
//   - 缓存写入失败不会影响主函数返回结果，错误会被忽略
//   - 即使缓存更新失败，主存储的数据仍然会成功保存
//
// 事务特性:
//   - 对主存储的写入具有事务性，要么完全成功要么完全失败
//   - 缓存更新不参与主存储的事务，缓存更新可能在主存储成功后失败
//
// 使用示例:
//
//	// 创建一个CPE对象
//	windowsCPE := &cpe.CPE{
//	    Cpe23:       "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
//	    Vendor:      cpe.Vendor("microsoft"),
//	    ProductName: cpe.Product("windows"),
//	    Version:     cpe.Version("10"),
//	}
//
//	// 使用存储管理器保存CPE
//	err := manager.StoreCPE(windowsCPE)
//	if err != nil {
//	    if errors.Is(err, cpe.ErrDuplicate) {
//	        fmt.Println("CPE已存在")
//	    } else {
//	        fmt.Printf("存储CPE失败: %v\n", err)
//	    }
//	    return
//	}
//	fmt.Println("CPE存储成功")
//
// 并发安全:
//   - 此方法的并发安全性取决于底层Storage实现
//   - 对于支持并发的Storage实现，此方法可以安全地并发调用
//
// 关联方法:
//   - GetCPE: 检索已存储的CPE
//   - ValidateCPE: 建议在存储前先验证CPE对象有效性
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

// GetCVE 获取CVE引用对象，优先从缓存获取
//
// 功能描述:
//   - 根据CVE ID检索对应的CVE引用对象
//   - 实现了两级存储查询策略: 如果缓存启用，优先从缓存查询，缓存未命中则从主存储查询
//   - 从主存储获取的数据会自动同步到缓存中，以便后续查询更快速
//
// 参数:
//   - cveID string: CVE的唯一标识符，标准格式如"CVE-2021-44228"
//   - 不能为空，否则可能导致未定义行为
//   - ID格式应符合CVE命名规范(CVE-YYYY-NNNNN)
//
// 返回值:
//   - *CVEReference: 成功检索到的CVE引用对象指针
//   - error: 如果检索失败则返回错误
//   - 可能的错误类型包括:
//   - ErrNotFound: 指定ID的CVE不存在
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 缓存行为:
//   - 如果缓存启用且缓存命中，直接返回缓存中的对象，不访问主存储
//   - 如果缓存启用但缓存未命中，从主存储获取并自动更新缓存
//   - 如果缓存未启用，或Cache为nil，直接从主存储获取
//
// 错误处理:
//   - 仅在主存储查询失败时返回错误，缓存查询失败会静默处理并继续查询主存储
//   - 将数据写入缓存失败不会影响返回结果，错误会被忽略
//
// 使用示例:
//
//	// 获取Log4Shell漏洞的CVE信息
//	log4jCVE, err := manager.GetCVE("CVE-2021-44228")
//	if err != nil {
//	    if errors.Is(err, cpe.ErrNotFound) {
//	        fmt.Println("CVE不存在")
//	    } else {
//	        fmt.Printf("获取CVE失败: %v\n", err)
//	    }
//	    return
//	}
//
//	// 使用获取到的CVE信息
//	fmt.Printf("漏洞描述: %s\n", log4jCVE.Description)
//	fmt.Printf("CVSS评分: %.1f\n", log4jCVE.CVSSScore)
//
// 性能考虑:
//   - 缓存命中时，性能显著优于直接从主存储查询
//   - 频繁查询相同CVE时，建议启用缓存
//
// 关联方法:
//   - FindCPEsByCVE: 查找受此CVE影响的所有CPE
//   - FindCVEsByCPE: 查找影响特定CPE的所有CVE
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

// Search 搜索匹配指定条件的CPE对象
//
// 功能描述:
//   - 在主存储中搜索符合给定条件的CPE对象
//   - 根据MatchOptions中的匹配规则进行过滤
//   - 直接从主存储搜索，不使用缓存，确保结果完整和最新
//
// 参数:
//   - criteria *CPE: 搜索条件，包含要匹配的CPE属性
//   - 可以为nil，表示不限制搜索条件(返回所有CPE)
//   - 如果指定了某个字段，则匹配该字段的值
//   - 特殊值"*"和"-"按CPE规范处理
//   - options *MatchOptions: 匹配选项，控制匹配行为
//   - 如果为nil，将使用默认匹配选项
//   - 包含精确匹配/模式匹配等控制参数
//
// 返回值:
//   - []*CPE: 匹配条件的CPE对象切片
//   - 如果没有匹配项，返回空切片(非nil)
//   - error: 如果搜索过程中发生错误则返回错误
//   - 可能的错误类型包括:
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 搜索行为:
//   - 此方法总是直接查询主存储，不使用缓存
//   - 查询结果不会被缓存，每次调用都会执行完整搜索
//   - 返回的CPE对象是数据库中对象的拷贝，修改不会影响存储
//
// 使用示例:
//
//	// 搜索所有Microsoft Windows产品的CPE
//	criteria := &cpe.CPE{
//	    Vendor:      cpe.Vendor("microsoft"),
//	    ProductName: cpe.Product("windows"),
//	}
//
//	// 使用默认匹配选项
//	options := &cpe.MatchOptions{}
//
//	// 执行搜索
//	results, err := manager.Search(criteria, options)
//	if err != nil {
//	    fmt.Printf("搜索失败: %v\n", err)
//	    return
//	}
//
//	// 处理搜索结果
//	fmt.Printf("找到 %d 个匹配项\n", len(results))
//	for i, cpe := range results {
//	    fmt.Printf("%d. %s\n", i+1, cpe.Cpe23)
//	}
//
// 性能考虑:
//   - 对于大型数据集，搜索可能需要较长时间，应考虑使用分页或限制结果数量
//   - 频繁执行相同搜索时，可考虑在应用层面实现结果缓存
//
// 关联方法:
//   - AdvancedSearch: 支持更复杂查询条件的高级搜索
//   - GetCPE: 根据ID直接获取单个CPE对象(支持缓存)
func (sm *StorageManager) Search(criteria *CPE, options *MatchOptions) ([]*CPE, error) {
	// 搜索不使用缓存，直接从主存储搜索
	return sm.Primary.SearchCPE(criteria, options)
}

// AdvancedSearch 高级搜索CPE对象
//
// 功能描述:
//   - 提供比基本Search更强大的CPE搜索功能
//   - 支持复杂的匹配条件和高级过滤规则
//   - 直接从主存储搜索，不使用缓存，确保结果完整和最新
//
// 参数:
//   - criteria *CPE: 搜索条件，包含要匹配的CPE属性
//   - 可以为nil，表示不限制搜索条件(返回所有CPE)
//   - 各个字段值将根据AdvancedMatchOptions中的规则进行匹配
//   - options *AdvancedMatchOptions: 高级匹配选项
//   - 不能为nil，必须提供有效的选项对象
//   - 包含高级匹配规则，如正则表达式匹配、版本范围匹配、逻辑组合条件等
//
// 返回值:
//   - []*CPE: 匹配条件的CPE对象切片
//   - 如果没有匹配项，返回空切片(非nil)
//   - error: 如果搜索过程中发生错误则返回错误
//   - 可能的错误类型包括:
//   - ErrInvalidData: 无效的搜索条件或匹配选项
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 搜索行为:
//   - 此方法总是直接查询主存储，不使用缓存
//   - 查询结果不会被缓存，每次调用都会执行完整搜索
//   - 根据高级匹配选项，可能会执行更复杂的数据库查询或内存过滤
//
// 使用示例:
//
//	// 高级搜索: 查找所有Microsoft的产品，版本在10.0到11.0之间
//	criteria := &cpe.CPE{
//	    Vendor: cpe.Vendor("microsoft"),
//	}
//
//	options := &cpe.AdvancedMatchOptions{
//	    VersionRange: &cpe.VersionRange{
//	        MinVersion: "10.0",
//	        MaxVersion: "11.0",
//	        Inclusive: true,
//	    },
//	    RegexMatch: map[string]string{
//	        "product": "windows|office",  // 产品名称匹配windows或office
//	    },
//	}
//
//	results, err := manager.AdvancedSearch(criteria, options)
//	if err != nil {
//	    fmt.Printf("高级搜索失败: %v\n", err)
//	    return
//	}
//
//	fmt.Printf("找到 %d 个匹配项\n", len(results))
//
// 性能考虑:
//   - 高级搜索通常比基本搜索消耗更多资源，尤其是使用正则表达式匹配时
//   - 对于大型数据集，应当限制结果数量或使用更具体的搜索条件
//
// 关联方法:
//   - Search: 基本搜索功能，适用于简单的精确匹配
func (sm *StorageManager) AdvancedSearch(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error) {
	// 高级搜索不使用缓存，直接从主存储搜索
	return sm.Primary.AdvancedSearchCPE(criteria, options)
}

// InvalidateCache 使指定CPE的缓存失效
//
// 功能描述:
//   - 从缓存中删除指定ID的CPE对象
//   - 用于在CPE数据更新后确保缓存与主存储一致
//   - 静默处理删除失败的情况，不影响程序流程
//
// 参数:
//   - id string: 要使其缓存失效的CPE的唯一标识符
//   - 通常为CPE 2.3格式的URI字符串
//   - 如果ID在缓存中不存在，操作不会产生任何效果
//
// 返回值:
//   - 无
//
// 缓存行为:
//   - 如果缓存未启用(CacheEnabled为false)，此方法不执行任何操作
//   - 如果Cache为nil，此方法不执行任何操作
//   - 缓存删除操作是尽力而为的，删除失败不会报告错误
//
// 使用场景:
//   - 当通过其他途径(非StorageManager)更新了CPE数据时
//   - 在执行UpdateCPE操作后手动调用，确保缓存一致性
//   - 当检测到数据不一致时主动清除缓存项
//
// 使用示例:
//
//	// 在更新CPE后，使缓存失效
//	cpeID := "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*"
//
//	// 通过其他方式更新了CPE数据
//	primaryStorage.UpdateCPE(updatedCPE)
//
//	// 使对应的缓存失效，确保下次获取时能获取最新数据
//	manager.InvalidateCache(cpeID)
//
//	// 下次调用GetCPE将从主存储获取最新数据
//	latestCPE, err := manager.GetCPE(cpeID)
//
// 并发安全:
//   - 此方法的并发安全性取决于Cache实现的DeleteCPE方法
//   - 对于多数实现，此方法可以安全地并发调用
//
// 关联方法:
//   - ClearCache: 清空整个缓存，而不是单个项
//   - GetCPE: 会受到此方法的影响，在缓存失效后将重新从主存储获取
func (sm *StorageManager) InvalidateCache(id string) {
	if sm.CacheEnabled && sm.Cache != nil {
		_ = sm.Cache.DeleteCPE(id) // 忽略缓存错误
	}
}

// ClearCache 清空存储管理器的所有缓存数据
//
// 功能描述:
//   - 清空整个缓存存储，移除所有缓存的CPE和CVE数据
//   - 通过重新初始化缓存存储来实现彻底清除
//   - 清除后，后续查询将从主存储获取最新数据
//
// 参数:
//   - 无
//
// 返回值:
//   - error: 清空缓存过程中发生的错误
//   - 如果缓存未启用或Cache为nil，返回nil
//   - 如果缓存初始化失败，返回相应错误
//
// 缓存行为:
//   - 如果缓存未启用(CacheEnabled为false)，此方法直接返回nil
//   - 如果Cache为nil，此方法直接返回nil
//   - 缓存清空是通过重新初始化缓存实现的，比单独删除每个项更高效
//
// 使用场景:
//   - 在数据大规模更新后使缓存完全失效
//   - 当检测到缓存和主存储严重不一致时
//   - 作为系统维护操作的一部分
//   - 在缓存可能已损坏的情况下重置缓存
//
// 使用示例:
//
//	// 清空缓存
//	err := manager.ClearCache()
//	if err != nil {
//	    fmt.Printf("清空缓存失败: %v\n", err)
//	    return
//	}
//	fmt.Println("缓存已清空")
//
//	// 之后的所有查询都将从主存储获取数据
//	cpe, err := manager.GetCPE("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*")
//
// 性能影响:
//   - 清空缓存后，后续的查询性能可能暂时下降，直到缓存重新填充
//   - 对于高访问量的系统，应在低峰期执行此操作
//
// 副作用:
//   - 导致所有已缓存的数据被丢弃
//   - 可能会触发大量的主存储查询，如果随后有大量访问请求
//
// 关联方法:
//   - InvalidateCache: 只使特定CPE缓存失效，而不是整个缓存
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

// GetStats 获取存储的统计信息
//
// 功能描述:
//   - 收集并返回存储系统的统计数据
//   - 包括CPE和CVE数据的数量、字典项数量和最后更新时间等信息
//   - 只从主存储中获取统计信息，不涉及缓存
//
// 参数:
//   - 无
//
// 返回值:
//   - *StorageStats: 包含各种统计信息的结构体指针
//   - TotalCPEs: 存储中的CPE总数
//   - TotalCVEs: 存储中的CVE总数
//   - TotalDictionaryItems: 字典中的项目总数
//   - StorageBytes: 存储占用的字节数(部分实现可能不提供)
//   - LastUpdated: 最后更新时间
//   - error: 如果统计过程中发生错误则返回错误
//   - 可能的错误类型包括:
//   - ErrStorageDisconnected: 存储后端连接问题
//   - 其他存储实现特定的错误
//
// 统计过程:
//   - 执行全量CPE搜索，获取CPE总数
//   - 执行全量CVE搜索，获取CVE总数
//   - 获取字典并计数字典项数量
//   - 获取最后更新时间，如果不存在则使用当前时间
//
// 使用示例:
//
//	// 获取存储统计信息
//	stats, err := manager.GetStats()
//	if err != nil {
//	    fmt.Printf("获取统计信息失败: %v\n", err)
//	    return
//	}
//
//	// 输出统计信息
//	fmt.Printf("CPE总数: %d\n", stats.TotalCPEs)
//	fmt.Printf("CVE总数: %d\n", stats.TotalCVEs)
//	fmt.Printf("字典项总数: %d\n", stats.TotalDictionaryItems)
//	fmt.Printf("最后更新时间: %v\n", stats.LastUpdated)
//
// 性能考虑:
//   - 此方法可能会执行多次全量查询，在大型数据集上可能较慢
//   - 不建议在高频操作中调用此方法，适合用于定期监控或管理界面
//
// 实现限制:
//   - 目前实现仅统计总数，不提供更详细的分布信息
//   - StorageBytes字段在当前实现中未填充实际值
//
// 关联信息:
//   - StorageStats: 存储统计信息的数据结构
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
