package cpe

type Part struct {
	ShortName   string
	LongName    string
	Description string
}

var (

	// PartApplication 应用，一般指的是软件
	PartApplication = &Part{
		ShortName:   "a",
		LongName:    "Application",
		Description: "",
	}

	// PartHardware 硬件
	PartHardware = &Part{
		ShortName:   "h",
		LongName:    "Hardware",
		Description: "",
	}

	// PartOperationSystem 操作系统
	PartOperationSystem = &Part{
		ShortName:   "o",
		LongName:    "Operation System",
		Description: "",
	}
)
