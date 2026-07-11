package cpeskills

import "strings"

// VendorNormalizer normalizes vendor and product names across different data sources.
//
// In vulnerability data, the same vendor/product may appear under different names:
//   - NVD: "apache" vs "apache_software_foundation"
//   - GitHub Advisory: "apache" vs "Apache Software Foundation"
//   - Different spellings, abbreviations, and corporate structure variations
//
// This normalizer maps all known aliases to a canonical form, enabling
// cross-data-source deduplication and fuzzy matching.
type VendorNormalizer struct {
	// canonical maps alias → canonical form for vendors
	canonicalVendor map[string]string

	// canonical maps alias → canonical form for products
	canonicalProduct map[string]string

	// vendorProducts maps canonical vendor → set of known products
	vendorProducts map[string]map[string]bool
}

// NewVendorNormalizer creates a new vendor normalizer with the built-in alias table.
func NewVendorNormalizer() *VendorNormalizer {
	n := &VendorNormalizer{
		canonicalVendor: make(map[string]string, 500),
		canonicalProduct: make(map[string]string, 1000),
		vendorProducts:   make(map[string]map[string]bool),
	}

	n.registerBuiltinAliases()
	return n
}

// NormalizeVendor returns the canonical vendor name.
func (n *VendorNormalizer) NormalizeVendor(name string) string {
	key := normalizeKey(name)
	if canonical, ok := n.canonicalVendor[key]; ok {
		return canonical
	}
	// If no alias match, treat the normalized form as canonical
	return canonicalForm(name)
}

// NormalizeProduct returns the canonical product name for a given vendor.
func (n *VendorNormalizer) NormalizeProduct(vendor, product string) string {
	key := normalizeKey(product)
	if canonical, ok := n.canonicalProduct[key]; ok {
		return canonical
	}
	return canonicalForm(product)
}

// NormalizeCPE normalizes a CPE's vendor and product to canonical form.
func (n *VendorNormalizer) NormalizeCPE(cpe *CPE) *CPE {
	if cpe == nil {
		return nil
	}

	normalized := Clone(cpe)
	normalized.Vendor = Vendor(n.NormalizeVendor(string(cpe.Vendor)))
	normalized.ProductName = Product(n.NormalizeProduct(string(cpe.Vendor), string(cpe.ProductName)))
	normalized.Cpe23 = FormatCpe23(normalized)

	return normalized
}

// AreSameVendor checks if two vendor names refer to the same entity.
func (n *VendorNormalizer) AreSameVendor(a, b string) bool {
	return n.NormalizeVendor(a) == n.NormalizeVendor(b)
}

// AreSameProduct checks if two products (from the same vendor) are the same.
func (n *VendorNormalizer) AreSameProduct(vendor, productA, productB string) bool {
	return n.NormalizeProduct(vendor, productA) == n.NormalizeProduct(vendor, productB)
}

// RegisterVendorAlias registers a new vendor alias.
func (n *VendorNormalizer) RegisterVendorAlias(canonical string, aliases ...string) {
	canonicalKey := canonicalForm(canonical)
	for _, alias := range aliases {
		n.canonicalVendor[normalizeKey(alias)] = canonicalKey
	}
	// Ensure canonical maps to itself
	n.canonicalVendor[normalizeKey(canonical)] = canonicalKey
}

// RegisterProductAlias registers a new product alias.
func (n *VendorNormalizer) RegisterProductAlias(canonical string, aliases ...string) {
	canonicalKey := canonicalForm(canonical)
	for _, alias := range aliases {
		n.canonicalProduct[normalizeKey(alias)] = canonicalKey
	}
	n.canonicalProduct[normalizeKey(canonical)] = canonicalKey
}

// HasVendor checks if a vendor is known.
func (n *VendorNormalizer) HasVendor(name string) bool {
	_, ok := n.canonicalVendor[normalizeKey(name)]
	return ok
}

// VendorCount returns the number of known vendor aliases.
func (n *VendorNormalizer) VendorCount() int {
	return len(n.canonicalVendor)
}

// registerBuiltinAliases populates the normalizer with common vendor/product aliases.
func (n *VendorNormalizer) registerBuiltinAliases() {
	// ===== Top Software Vendors =====

	// Apache Software Foundation
	n.RegisterVendorAlias("apache",
		"apache_software_foundation", "apache software foundation",
		"the apache software foundation", "apache foundation",
		"apache.org", "apache_software",
	)

	// Microsoft
	n.RegisterVendorAlias("microsoft",
		"microsoft_corporation", "microsoft corporation",
		"microsoft corp", "microsoft corp.", "ms", "msft",
		"microsoft_corp",
	)
	n.RegisterProductAlias("windows", "windows_10", "windows 10",
		"windows_11", "windows 11", "windows_server", "windows server",
		"win10", "win11", "microsoft_windows",
	)
	n.RegisterProductAlias("office", "microsoft_office", "ms_office",
		"office_365", "office365", "microsoft_365",
	)
	n.RegisterProductAlias(".net", "dotnet", ".net_framework", "dot_net",
		".net_core", "asp.net", "asp_net",
	)

	// Google
	n.RegisterVendorAlias("google",
		"google_inc", "google_llc", "google inc.", "google llc",
		"alphabet", "google_chrome",
	)
	n.RegisterProductAlias("chrome", "google_chrome", "chrome_browser",
		"google chrome", "chromium",
	)
	n.RegisterProductAlias("android", "google_android", "android_os",
		"android_platform",
	)

	// Oracle
	n.RegisterVendorAlias("oracle",
		"oracle_corporation", "oracle corporation",
		"oracle_corp", "oracle corp.",
	)
	n.RegisterProductAlias("java", "jre", "jdk", "java_runtime",
		"java_se", "java_jdk", "openjdk", "oracle_java",
	)
	n.RegisterProductAlias("mysql", "mysql_server", "mysql_database",
		"oracle_mysql",
	)

	// Red Hat
	n.RegisterVendorAlias("redhat",
		"red_hat", "red hat, inc.", "red hat inc",
		"red_hat_software", "rhel",
	)

	// Adobe
	n.RegisterVendorAlias("adobe",
		"adobe_systems", "adobe systems incorporated",
		"adobe_inc", "adobe inc.",
	)
	n.RegisterProductAlias("acrobat_reader", "adobe_acrobat_reader",
		"acrobat_reader_dc", "adobe_reader",
	)
	n.RegisterProductAlias("acrobat", "adobe_acrobat", "acrobat_dc",
		"acrobat_pro",
	)

	// IBM
	n.RegisterVendorAlias("ibm",
		"ibm_corporation", "ibm corporation",
		"ibm_corp", "international_business_machines",
	)

	// Cisco
	n.RegisterVendorAlias("cisco",
		"cisco_systems", "cisco systems, inc.",
		"cisco_inc", "cisco_systems_inc",
	)

	// VMware
	n.RegisterVendorAlias("vmware",
		"vmware_inc", "vmware, inc.", "broadcom", // VMware acquired by Broadcom
	)

	// Apple
	n.RegisterVendorAlias("apple",
		"apple_inc", "apple inc.", "apple_computer",
	)
	n.RegisterProductAlias("macos", "mac_os", "mac_os_x", "os_x",
		"apple_macos",
	)
	n.RegisterProductAlias("ios", "apple_ios", "iphone_os",
		"apple_ipad_os", "ipados",
	)

	// Mozilla
	n.RegisterVendorAlias("mozilla",
		"mozilla_foundation", "mozilla.org",
		"mozilla_corporation", "mozilla_project",
	)
	n.RegisterProductAlias("firefox", "mozilla_firefox", "firefox_browser",
		"firefox_esr",
	)

	// ===== Open Source Ecosystems =====

	// Python/PyPI
	n.RegisterVendorAlias("python",
		"python_software_foundation", "python.org", "pypa",
		"python_packaging_authority", "psf",
	)

	// Node.js / npm
	n.RegisterVendorAlias("nodejs",
		"node.js", "node.js_foundation", "npm", "npmjs",
		"openjs_foundation", "joyent",
	)

	// Go
	n.RegisterVendorAlias("golang",
		"golang.org", "google_go", "go_project",
	)

	// ===== Linux Distributions =====

	n.RegisterVendorAlias("debian", "debian_project", "debian.org")
	n.RegisterVendorAlias("ubuntu", "canonical", "ubuntu_linux")
	n.RegisterVendorAlias("fedora", "fedora_project", "fedora_linux")
	n.RegisterVendorAlias("centos", "centos_project", "centos_linux")
	n.RegisterVendorAlias("alpine", "alpine_linux", "alpinelinux")
	n.RegisterVendorAlias("suse", "novell", "opensuse", "suse_linux")
	n.RegisterVendorAlias("archlinux", "arch_linux", "arch")

	// ===== Database Systems =====

	n.RegisterVendorAlias("postgresql",
		"postgresql_global_development_group",
		"postgresql.org", "postgres",
	)
	n.RegisterVendorAlias("mariadb",
		"mariadb_foundation", "mariadb.org",
		"mariadb_corporation",
	)
	n.RegisterVendorAlias("sqlite", "sqlite.org", "sqlite_development_team")

	// ===== Common Product Aliases =====

	n.RegisterProductAlias("tomcat", "apache_tomcat", "jakarta_tomcat")
	n.RegisterProductAlias("log4j", "apache_log4j", "log4j2", "log4j-core")
	n.RegisterProductAlias("httpd", "apache_httpd", "apache_http_server",
		"http_server", "apache2",
	)
	n.RegisterProductAlias("openssl", "open_ssl", "openssl_crypto")
	n.RegisterProductAlias("openssh", "open_ssh", "openssh_server")
	n.RegisterProductAlias("nginx", "nginx_http_server", "nginx_plus")
	n.RegisterProductAlias("kubernetes", "k8s", "kube")
	n.RegisterProductAlias("docker", "docker_engine", "docker_ce",
		"docker_container", "moby",
	)
	n.RegisterProductAlias("django", "python_django", "django_framework")
	n.RegisterProductAlias("flask", "python_flask", "flask_framework")
	n.RegisterProductAlias("express", "express.js", "expressjs",
		"node_express", "node.js_express",
	)
	n.RegisterProductAlias("react", "react.js", "reactjs", "react_dom")
	n.RegisterProductAlias("vue", "vue.js", "vuejs")
	n.RegisterProductAlias("angular", "angular.js", "angularjs",
		"angular_core",
	)
	n.RegisterProductAlias("spring", "spring_framework", "spring_boot",
		"spring_mvc", "spring_security",
	)
	n.RegisterProductAlias("struts", "apache_struts", "struts2",
		"apache_struts2",
	)
	n.RegisterProductAlias("jquery", "jquery_ui", "jquery_javascript")
	n.RegisterProductAlias("bootstrap", "twitter_bootstrap",
		"bootstrap_framework",
	)
	n.RegisterProductAlias("lodash", "lodash.js", "lodash_javascript")
	n.RegisterProductAlias("wordpress", "word_press", "wp")
	n.RegisterProductAlias("drupal", "drupal_core", "drupal_cms")
	n.RegisterProductAlias("joomla", "joomla_cms", "joomla!")

	// ===== Programming Languages =====
	n.RegisterVendorAlias("php", "php_group", "php.net")
	n.RegisterVendorAlias("ruby", "ruby_lang", "ruby-lang.org")
	n.RegisterVendorAlias("rust", "rust_lang", "rust-lang.org")
	n.RegisterVendorAlias("perl", "perl_foundation", "perl.org")
}

// normalizeKey normalizes a string for use as a lookup key.
func normalizeKey(s string) string {
	s = strings.TrimSpace(s)
	// Replace common separators with underscore
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	// Collapse multiple underscores
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.ToLower(strings.Trim(s, "_"))
}

// canonicalForm returns the canonical form of a vendor/product name.
func canonicalForm(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	// Collapse underscores
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.ToLower(strings.Trim(s, "_"))
}

// GlobalVendorNormalizer is a package-level normalizer with built-in aliases.
var GlobalVendorNormalizer = NewVendorNormalizer()

// NormalizeVendorName is a convenience function using the global normalizer.
func NormalizeVendorName(name string) string {
	return GlobalVendorNormalizer.NormalizeVendor(name)
}

// NormalizeProductName is a convenience function using the global normalizer.
func NormalizeProductName(vendor, product string) string {
	return GlobalVendorNormalizer.NormalizeProduct(vendor, product)
}

// NormalizeCPE is a convenience function using the global normalizer.
func NormalizeCPEVendorProduct(cpe *CPE) *CPE {
	return GlobalVendorNormalizer.NormalizeCPE(cpe)
}
