package cpe

/**
 * Part 表示CPE标识中的组件类型
 *
 * 在CPE规范中，Part表示产品类型，可以是应用程序、硬件或操作系统。
 * 这是CPE标识的第一个组成部分，用于区分不同种类的IT产品。
 *
 * 属性:
 *   - ShortName: 单字符简称，在CPE URI中使用，如'a'、'h'、'o'
 *   - LongName: 完整名称，如'Application'、'Hardware'、'Operation System'
 *   - Description: 描述信息，提供关于该组件类型的附加说明
 *
 * 示例:
 *   ```go
 *   // 创建一个表示应用程序类型的CPE
 *   appCPE := &cpe.CPE{
 *       Part:        *cpe.PartApplication, // 使用预定义的应用程序类型
 *       Vendor:      cpe.Vendor("adobe"),
 *       ProductName: cpe.Product("acrobat_reader"),
 *   }
 *
 *   // 创建一个表示操作系统类型的CPE
 *   osCPE := &cpe.CPE{
 *       Part:        *cpe.PartOperationSystem, // 使用预定义的操作系统类型
 *       Vendor:      cpe.Vendor("microsoft"),
 *       ProductName: cpe.Product("windows"),
 *   }
 *   ```
 */
type Part struct {
	// 单字符简称，在CPE URI中使用，如'a'、'h'、'o'
	ShortName string

	// 完整名称，如'Application'、'Hardware'、'Operation System'
	LongName string

	// 描述信息，提供关于该组件类型的附加说明
	Description string
}

var (

	/**
	 * PartApplication 表示应用程序类型
	 *
	 * 用于标识软件应用程序，如办公软件、浏览器、数据库等。
	 * 在CPE URI中使用字符'a'表示。
	 *
	 * 示例:
	 *   ```go
	 *   // 表示Chrome浏览器的CPE
	 *   chromeCPE := &cpe.CPE{
	 *       Part:        *cpe.PartApplication,
	 *       Vendor:      cpe.Vendor("google"),
	 *       ProductName: cpe.Product("chrome"),
	 *   }
	 *   ```
	 */
	PartApplication = &Part{
		ShortName:   "a",
		LongName:    "Application",
		Description: "表示软件应用程序，包括但不限于桌面应用、服务器应用、移动应用等",
	}

	/**
	 * PartHardware 表示硬件设备类型
	 *
	 * 用于标识物理硬件设备，如路由器、打印机、服务器硬件等。
	 * 在CPE URI中使用字符'h'表示。
	 *
	 * 示例:
	 *   ```go
	 *   // 表示Cisco路由器的CPE
	 *   routerCPE := &cpe.CPE{
	 *       Part:        *cpe.PartHardware,
	 *       Vendor:      cpe.Vendor("cisco"),
	 *       ProductName: cpe.Product("rv340"),
	 *   }
	 *   ```
	 */
	PartHardware = &Part{
		ShortName:   "h",
		LongName:    "Hardware",
		Description: "表示物理硬件设备，包括但不限于网络设备、服务器、存储设备等",
	}

	/**
	 * PartOperationSystem 表示操作系统类型
	 *
	 * 用于标识操作系统，如Windows、Linux、macOS等。
	 * 在CPE URI中使用字符'o'表示。
	 *
	 * 示例:
	 *   ```go
	 *   // 表示Ubuntu Linux的CPE
	 *   ubuntuCPE := &cpe.CPE{
	 *       Part:        *cpe.PartOperationSystem,
	 *       Vendor:      cpe.Vendor("canonical"),
	 *       ProductName: cpe.Product("ubuntu_linux"),
	 *       Version:     cpe.Version("20.04"),
	 *   }
	 *   ```
	 */
	PartOperationSystem = &Part{
		ShortName:   "o",
		LongName:    "Operation System",
		Description: "表示操作系统，用于管理计算机硬件与软件资源的系统软件",
	}
)
