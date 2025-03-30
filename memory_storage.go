package cpe

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// MemoryStorage 是一个基于内存的存储实现
type MemoryStorage struct {
	// CPE存储，键为CPE ID
	cpes map[string]*CPE

	// CVE存储，键为CVE ID
	cves map[string]*CVEReference

	// CPE-CVE关联关系，键为CPE ID，值为CVE ID列表
	cpeToCVEs map[string][]string

	// CVE-CPE关联关系，键为CVE ID，值为CPE ID列表
	cveToCPEs map[string][]string

	// CPE字典
	dictionary *CPEDictionary

	// 修改时间戳
	timestamps map[string]time.Time

	// 互斥锁，用于线程安全操作
	mutex sync.RWMutex
}

// NewMemoryStorage 创建一个新的内存存储
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		cpes:       make(map[string]*CPE),
		cves:       make(map[string]*CVEReference),
		cpeToCVEs:  make(map[string][]string),
		cveToCPEs:  make(map[string][]string),
		dictionary: nil,
		timestamps: make(map[string]time.Time),
		mutex:      sync.RWMutex{},
	}
}

// Initialize 初始化存储
func (ms *MemoryStorage) Initialize() error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 清空所有存储
	ms.cpes = make(map[string]*CPE)
	ms.cves = make(map[string]*CVEReference)
	ms.cpeToCVEs = make(map[string][]string)
	ms.cveToCPEs = make(map[string][]string)
	ms.dictionary = nil
	ms.timestamps = make(map[string]time.Time)

	// 记录初始化时间
	ms.timestamps["initialization"] = time.Now()

	return nil
}

// Close 关闭存储连接
func (ms *MemoryStorage) Close() error {
	// 内存存储不需要关闭连接
	return nil
}

// StoreCPE 存储单个CPE
func (ms *MemoryStorage) StoreCPE(cpe *CPE) error {
	if cpe == nil {
		return ErrInvalidData
	}

	// 确保CPE有ID
	if cpe.GetURI() == "" {
		return fmt.Errorf("CPE must have a URI: %w", ErrInvalidData)
	}

	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 深拷贝CPE以防止外部修改
	cpeCopy := *cpe
	ms.cpes[cpe.GetURI()] = &cpeCopy

	// 更新时间戳
	ms.timestamps["last_cpe_update"] = time.Now()

	return nil
}

// RetrieveCPE 根据ID检索CPE
func (ms *MemoryStorage) RetrieveCPE(id string) (*CPE, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	cpe, ok := ms.cpes[id]
	if !ok {
		return nil, ErrNotFound
	}

	// 返回深拷贝以防止外部修改
	cpeCopy := *cpe
	return &cpeCopy, nil
}

// UpdateCPE 更新CPE
func (ms *MemoryStorage) UpdateCPE(cpe *CPE) error {
	if cpe == nil {
		return ErrInvalidData
	}

	// 确保CPE有ID
	if cpe.GetURI() == "" {
		return fmt.Errorf("CPE must have a URI: %w", ErrInvalidData)
	}

	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 检查CPE是否存在
	_, ok := ms.cpes[cpe.GetURI()]
	if !ok {
		return ErrNotFound
	}

	// 更新CPE
	cpeCopy := *cpe
	ms.cpes[cpe.GetURI()] = &cpeCopy

	// 更新时间戳
	ms.timestamps["last_cpe_update"] = time.Now()

	return nil
}

// DeleteCPE 删除CPE
func (ms *MemoryStorage) DeleteCPE(id string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 检查CPE是否存在
	_, ok := ms.cpes[id]
	if !ok {
		return ErrNotFound
	}

	// 删除CPE
	delete(ms.cpes, id)

	// 删除与此CPE关联的CVE关系
	delete(ms.cpeToCVEs, id)

	// 更新CVE-CPE关系
	for cveID, cpeIDs := range ms.cveToCPEs {
		var newCPEIDs []string
		for _, cpeID := range cpeIDs {
			if cpeID != id {
				newCPEIDs = append(newCPEIDs, cpeID)
			}
		}
		ms.cveToCPEs[cveID] = newCPEIDs
	}

	// 更新时间戳
	ms.timestamps["last_cpe_update"] = time.Now()

	return nil
}

// SearchCPE 搜索CPE
func (ms *MemoryStorage) SearchCPE(criteria *CPE, options *MatchOptions) ([]*CPE, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var results []*CPE

	// 如果没有查询条件，返回所有CPE
	if criteria == nil {
		for _, cpe := range ms.cpes {
			cpeCopy := *cpe
			results = append(results, &cpeCopy)
		}
		return results, nil
	}

	// 如果没有选项，使用默认选项
	if options == nil {
		options = &MatchOptions{}
	}

	// 搜索匹配的CPE
	for _, cpe := range ms.cpes {
		if MatchCPE(criteria, cpe, options) {
			cpeCopy := *cpe
			results = append(results, &cpeCopy)
		}
	}

	return results, nil
}

// AdvancedSearchCPE 高级搜索CPE
func (ms *MemoryStorage) AdvancedSearchCPE(criteria *CPE, options *AdvancedMatchOptions) ([]*CPE, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var results []*CPE

	// 如果没有查询条件，返回所有CPE
	if criteria == nil {
		for _, cpe := range ms.cpes {
			cpeCopy := *cpe
			results = append(results, &cpeCopy)
		}
		return results, nil
	}

	// 如果没有选项，使用默认选项
	if options == nil {
		options = &AdvancedMatchOptions{}
	}

	// 搜索匹配的CPE
	for _, cpe := range ms.cpes {
		if AdvancedMatchCPE(criteria, cpe, options) {
			cpeCopy := *cpe
			results = append(results, &cpeCopy)
		}
	}

	return results, nil
}

// StoreCVE 存储CVE信息
func (ms *MemoryStorage) StoreCVE(cve *CVEReference) error {
	if cve == nil {
		return ErrInvalidData
	}

	// 确保CVE有ID
	if cve.CVEID == "" {
		return fmt.Errorf("CVE must have an ID: %w", ErrInvalidData)
	}

	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 深拷贝CVE以防止外部修改
	cveCopy := *cve
	ms.cves[cve.CVEID] = &cveCopy

	// 更新CVE-CPE关系
	if len(cve.AffectedCPEs) > 0 {
		var cpeIDs []string
		for _, cpeName := range cve.AffectedCPEs {
			// Solo necesitamos verificar que el formato es válido
			var err error
			if strings.HasPrefix(cpeName, "cpe:2.3:") {
				_, err = ParseCpe23(cpeName)
			} else if strings.HasPrefix(cpeName, "cpe:/") {
				_, err = ParseCpe22(cpeName)
			} else {
				continue
			}
			if err == nil {
				cpeIDs = append(cpeIDs, cpeName)

				// 更新CPE-CVE关系
				ms.cpeToCVEs[cpeName] = append(ms.cpeToCVEs[cpeName], cve.CVEID)
			}
		}
		ms.cveToCPEs[cve.CVEID] = cpeIDs
	}

	// 更新时间戳
	ms.timestamps["last_cve_update"] = time.Now()

	return nil
}

// RetrieveCVE 根据CVE ID检索CVE信息
func (ms *MemoryStorage) RetrieveCVE(cveID string) (*CVEReference, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	cve, ok := ms.cves[cveID]
	if !ok {
		return nil, ErrNotFound
	}

	// 返回深拷贝以防止外部修改
	cveCopy := *cve
	return &cveCopy, nil
}

// UpdateCVE 更新CVE信息
func (ms *MemoryStorage) UpdateCVE(cve *CVEReference) error {
	if cve == nil {
		return ErrInvalidData
	}

	// 确保CVE有ID
	if cve.CVEID == "" {
		return fmt.Errorf("CVE must have an ID: %w", ErrInvalidData)
	}

	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 检查CVE是否存在
	_, ok := ms.cves[cve.CVEID]
	if !ok {
		return ErrNotFound
	}

	// 清除旧的CVE-CPE关系
	oldCPEIDs, ok := ms.cveToCPEs[cve.CVEID]
	if ok {
		for _, cpeID := range oldCPEIDs {
			// 从CPE-CVE关系中删除此CVE
			var newCVEIDs []string
			for _, id := range ms.cpeToCVEs[cpeID] {
				if id != cve.CVEID {
					newCVEIDs = append(newCVEIDs, id)
				}
			}
			ms.cpeToCVEs[cpeID] = newCVEIDs
		}
	}

	// 更新CVE
	cveCopy := *cve
	ms.cves[cve.CVEID] = &cveCopy

	// 更新CVE-CPE关系
	if len(cve.AffectedCPEs) > 0 {
		var cpeIDs []string
		for _, cpeName := range cve.AffectedCPEs {
			// Solo necesitamos verificar que el formato es válido
			var err error
			if strings.HasPrefix(cpeName, "cpe:2.3:") {
				_, err = ParseCpe23(cpeName)
			} else if strings.HasPrefix(cpeName, "cpe:/") {
				_, err = ParseCpe22(cpeName)
			} else {
				continue
			}
			if err == nil {
				cpeIDs = append(cpeIDs, cpeName)

				// 更新CPE-CVE关系
				ms.cpeToCVEs[cpeName] = append(ms.cpeToCVEs[cpeName], cve.CVEID)
			}
		}
		ms.cveToCPEs[cve.CVEID] = cpeIDs
	}

	// 更新时间戳
	ms.timestamps["last_cve_update"] = time.Now()

	return nil
}

// DeleteCVE 删除CVE信息
func (ms *MemoryStorage) DeleteCVE(cveID string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 检查CVE是否存在
	_, ok := ms.cves[cveID]
	if !ok {
		return ErrNotFound
	}

	// 删除CVE
	delete(ms.cves, cveID)

	// 清除CVE-CPE关系
	cpeIDs, ok := ms.cveToCPEs[cveID]
	if ok {
		for _, cpeID := range cpeIDs {
			// 从CPE-CVE关系中删除此CVE
			var newCVEIDs []string
			for _, id := range ms.cpeToCVEs[cpeID] {
				if id != cveID {
					newCVEIDs = append(newCVEIDs, id)
				}
			}
			ms.cpeToCVEs[cpeID] = newCVEIDs
		}
		delete(ms.cveToCPEs, cveID)
	}

	// 更新时间戳
	ms.timestamps["last_cve_update"] = time.Now()

	return nil
}

// SearchCVE 搜索CVE
func (ms *MemoryStorage) SearchCVE(query string, options *SearchOptions) ([]*CVEReference, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var results []*CVEReference

	// 如果没有选项，使用默认选项
	if options == nil {
		options = NewSearchOptions()
	}

	// 如果没有查询条件，返回所有CVE（但考虑分页）
	if query == "" {
		for _, cve := range ms.cves {
			// 应用过滤条件
			if ms.applyCVEFilters(cve, options) {
				cveCopy := *cve
				results = append(results, &cveCopy)
			}
		}
	} else {
		// 简单的文本匹配搜索
		query = strings.ToLower(query)
		for _, cve := range ms.cves {
			// 匹配CVE ID
			if strings.Contains(strings.ToLower(cve.CVEID), query) {
				// 应用过滤条件
				if ms.applyCVEFilters(cve, options) {
					cveCopy := *cve
					results = append(results, &cveCopy)
				}
				continue
			}

			// 匹配描述
			if strings.Contains(strings.ToLower(cve.Description), query) {
				// 应用过滤条件
				if ms.applyCVEFilters(cve, options) {
					cveCopy := *cve
					results = append(results, &cveCopy)
				}
				continue
			}

			// 匹配参考链接
			for _, ref := range cve.References {
				if strings.Contains(strings.ToLower(ref), query) {
					// 应用过滤条件
					if ms.applyCVEFilters(cve, options) {
						cveCopy := *cve
						results = append(results, &cveCopy)
					}
					break
				}
			}
		}
	}

	// 应用分页
	if options.Offset >= len(results) {
		return []*CVEReference{}, nil
	}

	end := options.Offset + options.Limit
	if end > len(results) {
		end = len(results)
	}

	return results[options.Offset:end], nil
}

// applyCVEFilters 应用CVE过滤条件
func (ms *MemoryStorage) applyCVEFilters(cve *CVEReference, options *SearchOptions) bool {
	// 检查CVSS评分范围
	if options.MinCVSS > 0 && cve.CVSSScore < options.MinCVSS {
		return false
	}

	if options.MaxCVSS > 0 && cve.CVSSScore > options.MaxCVSS {
		return false
	}

	// 检查日期范围
	if options.DateStart != nil && cve.PublishedDate.Before(*options.DateStart) {
		return false
	}

	if options.DateEnd != nil && cve.PublishedDate.After(*options.DateEnd) {
		return false
	}

	// 检查自定义过滤条件
	for key, value := range options.Filters {
		switch key {
		case "severity":
			if severity, ok := value.(string); ok && severity != cve.Severity {
				return false
			}
		case "vendor":
			if vendor, ok := value.(string); ok {
				found := false
				for _, cpeName := range cve.AffectedCPEs {
					var cpe *CPE
					var err error
					if strings.HasPrefix(cpeName, "cpe:2.3:") {
						cpe, err = ParseCpe23(cpeName)
					} else if strings.HasPrefix(cpeName, "cpe:/") {
						cpe, err = ParseCpe22(cpeName)
					} else {
						continue
					}
					if err == nil && string(cpe.Vendor) == vendor {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		case "product":
			if product, ok := value.(string); ok {
				found := false
				for _, cpeName := range cve.AffectedCPEs {
					var cpe *CPE
					var err error
					if strings.HasPrefix(cpeName, "cpe:2.3:") {
						cpe, err = ParseCpe23(cpeName)
					} else if strings.HasPrefix(cpeName, "cpe:/") {
						cpe, err = ParseCpe22(cpeName)
					} else {
						continue
					}
					if err == nil && string(cpe.ProductName) == product {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}

	return true
}

// FindCVEsByCPE 查找与CPE关联的CVE
func (ms *MemoryStorage) FindCVEsByCPE(cpe *CPE) ([]*CVEReference, error) {
	if cpe == nil {
		return nil, ErrInvalidData
	}

	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var results []*CVEReference
	cpeURI := cpe.GetURI()

	// 获取与此CPE关联的CVE ID列表
	cveIDs, ok := ms.cpeToCVEs[cpeURI]
	if !ok {
		// 如果找不到精确匹配，尝试按照CPE规则进行匹配
		for storedCPEURI, storedCVEIDs := range ms.cpeToCVEs {
			var storedCPE *CPE
			var err error
			if strings.HasPrefix(storedCPEURI, "cpe:2.3:") {
				storedCPE, err = ParseCpe23(storedCPEURI)
			} else if strings.HasPrefix(storedCPEURI, "cpe:/") {
				storedCPE, err = ParseCpe22(storedCPEURI)
			} else {
				continue
			}
			if err != nil {
				continue
			}

			if MatchCPE(cpe, storedCPE, &MatchOptions{}) {
				cveIDs = append(cveIDs, storedCVEIDs...)
			}
		}

		// 如果仍然没有结果，返回空列表
		if len(cveIDs) == 0 {
			return []*CVEReference{}, nil
		}
	}

	// 检索CVE详情
	for _, cveID := range cveIDs {
		cve, ok := ms.cves[cveID]
		if ok {
			cveCopy := *cve
			results = append(results, &cveCopy)
		}
	}

	return results, nil
}

// FindCPEsByCVE 查找与CVE关联的CPE
func (ms *MemoryStorage) FindCPEsByCVE(cveID string) ([]*CPE, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var results []*CPE

	// 获取与此CVE关联的CPE ID列表
	cpeIDs, ok := ms.cveToCPEs[cveID]
	if !ok {
		return []*CPE{}, nil
	}

	// 检索CPE详情
	for _, cpeID := range cpeIDs {
		cpe, ok := ms.cpes[cpeID]
		if ok {
			cpeCopy := *cpe
			results = append(results, &cpeCopy)
		}
	}

	return results, nil
}

// StoreDictionary 存储CPE字典
func (ms *MemoryStorage) StoreDictionary(dict *CPEDictionary) error {
	if dict == nil {
		return ErrInvalidData
	}

	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// 存储字典的深拷贝
	dictCopy := *dict
	ms.dictionary = &dictCopy

	// 更新时间戳
	ms.timestamps["last_dictionary_update"] = time.Now()

	return nil
}

// RetrieveDictionary 检索CPE字典
func (ms *MemoryStorage) RetrieveDictionary() (*CPEDictionary, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	if ms.dictionary == nil {
		return nil, ErrNotFound
	}

	// 返回字典的深拷贝
	dictCopy := *ms.dictionary
	return &dictCopy, nil
}

// StoreModificationTimestamp 存储最后修改时间
func (ms *MemoryStorage) StoreModificationTimestamp(key string, timestamp time.Time) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	ms.timestamps[key] = timestamp

	return nil
}

// RetrieveModificationTimestamp 检索最后修改时间
func (ms *MemoryStorage) RetrieveModificationTimestamp(key string) (time.Time, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	timestamp, ok := ms.timestamps[key]
	if !ok {
		return time.Time{}, ErrNotFound
	}

	return timestamp, nil
}

// ParseURI 根据URI格式解析CPE
func ParseURI(uri string) (*CPE, error) {
	if strings.HasPrefix(uri, "cpe:2.3:") {
		return ParseCpe23(uri)
	} else if strings.HasPrefix(uri, "cpe:/") {
		return ParseCpe22(uri)
	}
	return nil, NewInvalidFormatError(uri)
}
