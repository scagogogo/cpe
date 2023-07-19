package cpe

import (
	"fmt"
	"strings"
)

const CPE23Header = "cpe"
const CPE23Version = "2.3"

// ParseCpe23 解析cpe2.3字符串
// cpe:2.3:a:limesurvey:limesurvey:3.4.2:*:*:*:*:*:*:*
func ParseCpe23(cpe23 string) (*CPE, error) {
	split := strings.Split(cpe23, ":")
	if len(split) != 13 {
		return nil, fmt.Errorf("string %s not a legal CPE2.3 string", cpe23)
	}

	// 文件头检查
	if strings.ToLower(split[0]) != CPE23Header {
		return nil, fmt.Errorf("string %s not a legal CPE2.3 string", cpe23)
	}
	// 版本检查
	if split[1] != CPE23Version {
		return nil, fmt.Errorf("string %s not a legal CPE2.3 string", cpe23)
	}

	return &CPE{
		Cpe23:           cpe23,
		Part:            Part(split[2]),
		Vendor:          split[3],
		ProductName:     split[4],
		Version:         split[5],
		Update:          split[6],
		Edition:         split[7],
		Language:        split[8],
		SoftwareEdition: split[9],
		TargetSoftware:  split[10],
		TargetHardware:  split[11],
		Other:           split[12],
	}, nil
}


// cpe:/a:baidu_tongji_generator_project:baidu_tongji_generator:::~~~wordpress~~
