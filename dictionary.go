package cpe

import (
	"encoding/xml"
	"io"
	"strings"
	"time"
)

/**
 * CPEDictionary 表示CPE字典，管理和存储CPE项集合
 *
 * CPE字典是一个包含多个CPE项的集合，常用于存储和管理来自官方NVD CPE字典或自定义
 * CPE集合的数据。字典包含元数据如生成时间和版本，以及CPE项列表。
 *
 * 主要用途:
 *   1. 存储从NVD或其他来源下载的CPE数据
 *   2. 对CPE进行批量管理和查询
 *   3. 保存CPE集合的元数据，如生成时间和版本
 *
 * 示例:
 *   ```go
 *   // 创建一个新的CPE字典
 *   dict := &cpe.CPEDictionary{
 *       GeneratedAt:    time.Now(),
 *       SchemaVersion:  "2.3",
 *       Items:          make([]*cpe.CPEItem, 0),
 *   }
 *
 *   // 添加CPE项
 *   windowsCPE, _ := cpe.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
 *   dictItem := &cpe.CPEItem{
 *       Name:  windowsCPE.Cpe23,
 *       Title: "Microsoft Windows 10",
 *       CPE:   windowsCPE,
 *   }
 *   dict.Items = append(dict.Items, dictItem)
 *
 *   // 保存字典到存储
 *   storage, _ := cpe.NewFileStorage("/tmp/cpe-storage", true)
 *   err := storage.StoreDictionary(dict)
 *   if err != nil {
 *       log.Fatalf("保存字典失败: %v", err)
 *   }
 *   ```
 */
type CPEDictionary struct {
	// 字典中的CPE项列表
	Items []*CPEItem `json:"items" bson:"items"`

	// 字典生成时间
	GeneratedAt time.Time `json:"generated_at" bson:"generated_at"`

	// 字典符合的CPE规范版本
	SchemaVersion string `json:"schema_version" bson:"schema_version"`
}

/**
 * CPEItem 表示字典中的单个CPE条目
 *
 * 每个CPEItem包含一个CPE及其相关元数据，如名称、标题、参考信息和弃用状态。
 * 这些项通常来自NVD CPE字典或其他来源，保留了原始数据的丰富信息。
 */
type CPEItem struct {
	// CPE的标准名称（通常是CPE 2.3格式）
	Name string `json:"name" xml:"name" bson:"name"`

	// CPE的人类可读标题
	Title string `json:"title" xml:"title" bson:"title"`

	// 相关参考信息列表
	References []Reference `json:"references" xml:"references>reference" bson:"references"`

	// 是否已弃用
	Deprecated bool `json:"deprecated" xml:"deprecated,attr" bson:"deprecated"`

	// 弃用日期（如果已弃用）
	DeprecationDate *time.Time `json:"deprecation_date" xml:"deprecation_date" bson:"deprecation_date"`

	// 解析后的CPE对象
	CPE *CPE `json:"cpe" bson:"cpe"`
}

/**
 * Reference 表示CPE项的参考信息
 *
 * 每个Reference包含一个指向额外信息的URL和引用类型，
 * 通常指向供应商网站、文档或其他资源。
 */
type Reference struct {
	// 参考URL
	URL string `json:"url" xml:"href,attr" bson:"url"`

	// 参考类型，如"Vendor", "Advisory", "External"等
	Type string `json:"type" xml:"type" bson:"type"`
}

// 以下是用于XML解析的结构体

// XMLCPEDictionary XML格式的CPE字典（用于解析）
type XMLCPEDictionary struct {
	XMLName       xml.Name     `xml:"cpe-list"`
	SchemaVersion string       `xml:"schema_version,attr"`
	GeneratedAt   string       `xml:"generated,attr"`
	Items         []XMLCPEItem `xml:"cpe-item"`
}

// XMLCPEItem XML格式的CPE项
type XMLCPEItem struct {
	XMLName         xml.Name       `xml:"cpe-item"`
	Name            string         `xml:"name,attr"`
	Deprecated      string         `xml:"deprecated,attr,omitempty"`
	DeprecationDate string         `xml:"deprecation_date,attr,omitempty"`
	Title           string         `xml:"title"`
	References      []XMLReference `xml:"references>reference,omitempty"`
}

// XMLReference XML格式的参考信息
type XMLReference struct {
	URL  string `xml:"href,attr"`
	Type string `xml:"type,attr"`
}

/**
 * ParseDictionary 从XML数据解析CPE字典
 *
 * 此函数读取符合NVD CPE Dictionary XML格式的数据流，解析并转换为内部CPEDictionary结构。
 * 解析过程包括处理CPE项、生成时间、弃用信息和参考链接等。
 *
 * @param r io.Reader XML数据流，通常来自文件或HTTP响应
 * @return (*CPEDictionary, error) 成功时返回解析的字典和nil错误，失败时返回nil和错误
 *
 * @error 解析XML失败时返回OperationFailedError
 *
 * 示例:
 *   ```go
 *   // 从文件读取CPE字典XML
 *   file, err := os.Open("official-cpe-dictionary_v2.3.xml")
 *   if err != nil {
 *       log.Fatalf("打开字典文件失败: %v", err)
 *   }
 *   defer file.Close()
 *
 *   // 解析字典
 *   dictionary, err := cpe.ParseDictionary(file)
 *   if err != nil {
 *       log.Fatalf("解析字典失败: %v", err)
 *   }
 *
 *   // 使用解析后的字典
 *   fmt.Printf("字典包含 %d 个CPE项\n", len(dictionary.Items))
 *   fmt.Printf("字典生成于: %v\n", dictionary.GeneratedAt)
 *
 *   // 查看前5个CPE项
 *   for i, item := range dictionary.Items[:5] {
 *       fmt.Printf("%d. %s - %s\n", i+1, item.Name, item.Title)
 *   }
 *   ```
 */
func ParseDictionary(r io.Reader) (*CPEDictionary, error) {
	var xmlDict XMLCPEDictionary
	decoder := xml.NewDecoder(r)
	err := decoder.Decode(&xmlDict)
	if err != nil {
		return nil, NewOperationFailedError("parse dictionary", err)
	}

	// 转换为内部字典格式
	dict := &CPEDictionary{
		SchemaVersion: xmlDict.SchemaVersion,
		Items:         make([]*CPEItem, 0, len(xmlDict.Items)),
	}

	// 解析生成时间
	if xmlDict.GeneratedAt != "" {
		generatedTime, err := time.Parse(time.RFC3339, xmlDict.GeneratedAt)
		if err == nil {
			dict.GeneratedAt = generatedTime
		}
	}

	// 转换每个CPE项
	for _, xmlItem := range xmlDict.Items {
		item := &CPEItem{
			Name:  xmlItem.Name,
			Title: xmlItem.Title,
		}

		// 解析CPE
		if strings.HasPrefix(xmlItem.Name, "cpe:/") {
			// CPE 2.2格式
			cpe, err := ParseCpe22(xmlItem.Name)
			if err == nil {
				item.CPE = cpe
			}
		} else if strings.HasPrefix(xmlItem.Name, "cpe:2.3:") {
			// CPE 2.3格式
			cpe, err := ParseCpe23(xmlItem.Name)
			if err == nil {
				item.CPE = cpe
			}
		}

		// 解析弃用状态
		if xmlItem.Deprecated == "true" {
			item.Deprecated = true

			// 解析弃用时间
			if xmlItem.DeprecationDate != "" {
				deprecationTime, err := time.Parse(time.RFC3339, xmlItem.DeprecationDate)
				if err == nil {
					item.DeprecationDate = &deprecationTime
				}
			}
		}

		// 转换参考信息
		for _, xmlRef := range xmlItem.References {
			ref := Reference{
				URL:  xmlRef.URL,
				Type: xmlRef.Type,
			}
			item.References = append(item.References, ref)
		}

		dict.Items = append(dict.Items, item)
	}

	return dict, nil
}

// ExportDictionary 将CPE字典导出为XML格式
func ExportDictionary(dict *CPEDictionary, w io.Writer) error {
	// 创建XML字典结构
	xmlDict := XMLCPEDictionary{
		SchemaVersion: dict.SchemaVersion,
		GeneratedAt:   dict.GeneratedAt.Format(time.RFC3339),
		Items:         make([]XMLCPEItem, 0, len(dict.Items)),
	}

	// 转换每个CPE项
	for _, item := range dict.Items {
		xmlItem := XMLCPEItem{
			Name:  item.Name,
			Title: item.Title,
		}

		// 设置弃用信息
		if item.Deprecated {
			xmlItem.Deprecated = "true"
			if item.DeprecationDate != nil {
				xmlItem.DeprecationDate = item.DeprecationDate.Format(time.RFC3339)
			}
		}

		// 转换参考信息
		for _, ref := range item.References {
			xmlRef := XMLReference{
				URL:  ref.URL,
				Type: ref.Type,
			}
			xmlItem.References = append(xmlItem.References, xmlRef)
		}

		xmlDict.Items = append(xmlDict.Items, xmlItem)
	}

	// 生成XML
	encoder := xml.NewEncoder(w)
	encoder.Indent("", "  ")

	_, err := w.Write([]byte(xml.Header))
	if err != nil {
		return NewOperationFailedError("write XML header", err)
	}

	err = encoder.Encode(xmlDict)
	if err != nil {
		return NewOperationFailedError("encode dictionary", err)
	}

	return nil
}

// FindItemByName 根据CPE名称查找字典项
func (d *CPEDictionary) FindItemByName(name string) *CPEItem {
	for _, item := range d.Items {
		if item.Name == name {
			return item
		}
	}
	return nil
}

// FindItemsByCriteria 根据条件查找字典项
func (d *CPEDictionary) FindItemsByCriteria(criteria *CPE, options *MatchOptions) []*CPEItem {
	var results []*CPEItem

	for _, item := range d.Items {
		if item.CPE != nil && matchCPE(item.CPE, criteria, options) {
			results = append(results, item)
		}
	}

	return results
}

// AddItem 添加CPE项到字典
func (d *CPEDictionary) AddItem(item *CPEItem) {
	// 检查是否已存在同名项
	for i, existing := range d.Items {
		if existing.Name == item.Name {
			// 替换现有项
			d.Items[i] = item
			return
		}
	}

	// 添加新项
	d.Items = append(d.Items, item)
}

// RemoveItem 从字典中移除CPE项
func (d *CPEDictionary) RemoveItem(name string) bool {
	for i, item := range d.Items {
		if item.Name == name {
			// 移除项
			d.Items = append(d.Items[:i], d.Items[i+1:]...)
			return true
		}
	}
	return false
}

// NewCPEItem 创建新的CPE项
func NewCPEItem(cpe *CPE, title string) *CPEItem {
	var name string
	if cpe.Cpe23 != "" {
		name = cpe.Cpe23
	} else {
		name = FormatCpe23(cpe)
	}

	return &CPEItem{
		Name:  name,
		Title: title,
		CPE:   cpe,
	}
}
