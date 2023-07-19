package cpe

// CPE 表示一条CPE信息
// cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
type CPE struct {

	// cpe 2.3版本的编号，目前只有2.3版本
	Cpe23 string `json:"cpe_23" bson:"cpe_23"`

	// a是应用，h是硬件平台，o是操作系统
	Part Part `json:"part" bson:"part"`

	// 产品的厂商的名字
	Vendor Vendor `json:"vendor" bson:"vendor"`

	// 产品的名字
	ProductName Product `json:"product_name" bson:"product_name"`

	// 版本
	Version Version `json:"version" bson:"version"`

	Update Update `json:"update" bson:"update"`

	Edition Edition `json:"edition" bson:"edition"`

	Language Language `json:"language" bson:"language"`

	SoftwareEdition string `json:"software_edition" bson:"software_edition"`

	TargetSoftware string `json:"target_software" bson:"target_software"`

	TargetHardware string `json:"target_hardware" bson:"target_hardware"`

	Other string `json:"other" bson:"other"`

	// cpe所对应的 cve 编号
	Cve string `json:"cve" bson:"cve"`

	// 此条映射关系是从哪个页面上得到的
	Url string `json:"url" bson:"url"`
}

// 判断是否匹配CVE
func (x *CPE) Match() {

}
