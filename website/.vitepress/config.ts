import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

const GITHUB = 'https://github.com/scagogogo/cpe-skills'

// Module groupings shared by both locales (links are language-agnostic paths)
const moduleGroups = (p) => [
  {
    text: 'Parsing & Types',
    collapsed: true,
    items: [
      { text: 'CPE', link: `${p}cpe` },
      { text: 'Parser 2.2', link: `${p}parser-2.2` },
      { text: 'Parser 2.3', link: `${p}parser-2.3` },
      { text: 'Convenience', link: `${p}convenience` },
      { text: 'Generator', link: `${p}generator` },
      { text: 'Builder', link: `${p}builder` },
      { text: 'Component', link: `${p}component` },
      { text: 'Part', link: `${p}part` },
      { text: 'WFN', link: `${p}wfn` },
      { text: 'Binding', link: `${p}binding` },
      { text: 'Escaping', link: `${p}escaping` },
      { text: 'Validation', link: `${p}validation` }
    ]
  },
  {
    text: 'Matching & Search',
    collapsed: true,
    items: [
      { text: 'Matching', link: `${p}matching` },
      { text: 'Advanced Matching', link: `${p}advanced-matching` },
      { text: 'Applicability', link: `${p}applicability` },
      { text: 'Search', link: `${p}search` },
      { text: 'Batch', link: `${p}batch` },
      { text: 'Set', link: `${p}set` },
      { text: 'Vendor Normalization', link: `${p}vendor-normalization` },
      { text: 'Version Compare', link: `${p}version-compare` }
    ]
  },
  {
    text: 'Storage & Index',
    collapsed: true,
    items: [
      { text: 'Storage', link: `${p}storage` },
      { text: 'Memory Storage', link: `${p}memory-storage` },
      { text: 'File Storage', link: `${p}file-storage` },
      { text: 'CPE Index', link: `${p}cpe-index` },
      { text: 'Dictionary', link: `${p}dictionary` }
    ]
  },
  {
    text: 'Vulnerability Data',
    collapsed: true,
    items: [
      { text: 'Datasource', link: `${p}datasource` },
      { text: 'NVD', link: `${p}nvd` },
      { text: 'CVE', link: `${p}cve` },
      { text: 'OSV', link: `${p}osv` },
      { text: 'EPSS', link: `${p}epss` },
      { text: 'KEV', link: `${p}kev` }
    ]
  },
  {
    text: 'SBOM & VEX',
    collapsed: true,
    items: [
      { text: 'SBOM', link: `${p}sbom` },
      { text: 'SBOM CycloneDX', link: `${p}sbom-cyclonedx` },
      { text: 'SBOM SPDX', link: `${p}sbom-spdx` },
      { text: 'SBOM Enhanced', link: `${p}sbom-enhanced` },
      { text: 'VEX', link: `${p}vex` },
      { text: 'Vulnerability Report', link: `${p}vulnerability-report` },
      { text: 'Risk Scoring', link: `${p}risk-scoring` },
      { text: 'Dependency Graph', link: `${p}dependency-graph` },
      { text: 'Reachability', link: `${p}reachability` },
      { text: 'Remediation', link: `${p}remediation` }
    ]
  },
  {
    text: 'PURL & Ecosystem',
    collapsed: true,
    items: [
      { text: 'PURL', link: `${p}purl` },
      { text: 'CPE-PURL Mapping', link: `${p}cpe-purl-mapping` },
      { text: 'Ecosystem', link: `${p}ecosystem` },
      { text: 'Manifest Bridge', link: `${p}manifest-bridge` }
    ]
  },
  {
    text: 'Export & Utilities',
    collapsed: true,
    items: [
      { text: 'Export', link: `${p}export` },
      { text: 'Errors', link: `${p}errors` },
      { text: 'Logger', link: `${p}logger` },
      { text: 'License', link: `${p}license` },
      { text: 'License Detection', link: `${p}license-detection` }
    ]
  }
]

const enConcepts = [
  { text: 'CPE Overview', link: '/en/concepts/cpe-overview' },
  { text: 'CPE 2.2 vs 2.3', link: '/en/concepts/cpe-22-vs-23' },
  { text: 'WFN', link: '/en/concepts/wfn' },
  { text: 'Matching Relations', link: '/en/concepts/matching-relations' },
  { text: 'Package URL', link: '/en/concepts/purl' },
  { text: 'SBOM Standards', link: '/en/concepts/sbom-standards' },
  { text: 'VEX', link: '/en/concepts/vex' },
  { text: 'EPSS & KEV', link: '/en/concepts/epss-kev' },
  { text: 'CVE Naming', link: '/en/concepts/cve-naming' },
  { text: 'NVD', link: '/en/concepts/nvd' },
  { text: 'OSV', link: '/en/concepts/osv' },
  { text: 'Risk Scoring', link: '/en/concepts/risk-scoring' },
  { text: 'Dependency Graph', link: '/en/concepts/dependency-graph' },
  { text: 'Vendor Normalization', link: '/en/concepts/vendor-normalization' },
  { text: 'Version Semantics', link: '/en/concepts/version-semantics' },
  { text: 'Storage Backends', link: '/en/concepts/storage-backends' },
  { text: 'FAQ', link: '/en/concepts/faq' },
  { text: 'Best Practices', link: '/en/concepts/best-practices' },
  { text: 'Error Handling', link: '/en/concepts/error-handling' },
  { text: 'Performance', link: '/en/concepts/performance' },
  { text: 'Migrate 2.2 → 2.3', link: '/en/concepts/migration-2.2-to-2.3' },
  { text: 'Integration Paths', link: '/en/concepts/integration-paths' },
  { text: 'Security Use Cases', link: '/en/concepts/security-use-cases' },
  { text: 'Glossary', link: '/en/concepts/glossary' },
  { text: 'Parsing Examples', link: '/en/concepts/parsing-examples' },
  { text: 'Matching Examples', link: '/en/concepts/matching-examples' },
  { text: 'Builder Examples', link: '/en/concepts/builder-examples' },
  { text: 'Set Examples', link: '/en/concepts/set-examples' },
  { text: 'Storage Examples', link: '/en/concepts/storage-examples' },
  { text: 'Generation Examples', link: '/en/concepts/generation-examples' },
  { text: 'Normalization Examples', link: '/en/concepts/normalization-examples' }
]

const enTutorials = [
  { text: 'Identify Vulnerabilities', link: '/en/tutorials/identify-vulnerabilities' },
  { text: 'Build an SBOM', link: '/en/tutorials/build-sbom' },
  { text: 'CI Scanning', link: '/en/tutorials/ci-scanning' },
  { text: 'MCP & AI Integration', link: '/en/tutorials/mcp-ai-integration' },
  { text: 'Batch Scanning', link: '/en/tutorials/batch-scanning' },
  { text: 'Version Range Filtering', link: '/en/tutorials/version-range-filtering' },
  { text: 'VEX Generation', link: '/en/tutorials/vex-generation' },
  { text: 'CPE–PURL Bridging', link: '/en/tutorials/cpe-purl-bridging' },
  { text: 'Storage Strategies', link: '/en/tutorials/storage-strategies' }
]

const zhConcepts = [
  { text: 'CPE 概览', link: '/zh/concepts/cpe-overview' },
  { text: 'CPE 2.2 vs 2.3', link: '/zh/concepts/cpe-22-vs-23' },
  { text: 'WFN', link: '/zh/concepts/wfn' },
  { text: '匹配关系', link: '/zh/concepts/matching-relations' },
  { text: 'Package URL', link: '/zh/concepts/purl' },
  { text: 'SBOM 标准', link: '/zh/concepts/sbom-standards' },
  { text: 'VEX', link: '/zh/concepts/vex' },
  { text: 'EPSS 与 KEV', link: '/zh/concepts/epss-kev' },
  { text: 'CVE 命名', link: '/zh/concepts/cve-naming' },
  { text: 'NVD', link: '/zh/concepts/nvd' },
  { text: 'OSV', link: '/zh/concepts/osv' },
  { text: '风险评分', link: '/zh/concepts/risk-scoring' },
  { text: '依赖图', link: '/zh/concepts/dependency-graph' },
  { text: '厂商名规范化', link: '/zh/concepts/vendor-normalization' },
  { text: '版本语义', link: '/zh/concepts/version-semantics' },
  { text: '存储后端', link: '/zh/concepts/storage-backends' },
  { text: '常见问题', link: '/zh/concepts/faq' },
  { text: '最佳实践', link: '/zh/concepts/best-practices' },
  { text: '错误处理', link: '/zh/concepts/error-handling' },
  { text: '性能考量', link: '/zh/concepts/performance' },
  { text: '2.2 → 2.3 迁移', link: '/zh/concepts/migration-2.2-to-2.3' },
  { text: '集成路径', link: '/zh/concepts/integration-paths' },
  { text: '安全用例', link: '/zh/concepts/security-use-cases' },
  { text: '术语表', link: '/zh/concepts/glossary' },
  { text: '解析示例集', link: '/zh/concepts/parsing-examples' },
  { text: '匹配示例集', link: '/zh/concepts/matching-examples' },
  { text: '构建器示例集', link: '/zh/concepts/builder-examples' },
  { text: '集合示例集', link: '/zh/concepts/set-examples' },
  { text: '存储示例集', link: '/zh/concepts/storage-examples' },
  { text: '生成示例集', link: '/zh/concepts/generation-examples' },
  { text: '规范化示例集', link: '/zh/concepts/normalization-examples' }
]

const zhTutorials = [
  { text: '识别漏洞', link: '/zh/tutorials/identify-vulnerabilities' },
  { text: '构建 SBOM', link: '/zh/tutorials/build-sbom' },
  { text: 'CI 扫描', link: '/zh/tutorials/ci-scanning' },
  { text: 'MCP 与 AI 集成', link: '/zh/tutorials/mcp-ai-integration' },
  { text: '批量扫描', link: '/zh/tutorials/batch-scanning' },
  { text: '版本范围过滤', link: '/zh/tutorials/version-range-filtering' },
  { text: 'VEX 生成', link: '/zh/tutorials/vex-generation' },
  { text: 'CPE–PURL 桥接', link: '/zh/tutorials/cpe-purl-bridging' },
  { text: '存储策略', link: '/zh/tutorials/storage-strategies' }
]

const enSidebar = {
  '/en/api/': [
    {
      text: 'API Reference',
      items: [
        { text: 'Overview', link: '/en/api/' },
        { text: 'Core Types', link: '/en/api/types' },
        { text: 'Parsing', link: '/en/api/parsing' },
        { text: 'Matching', link: '/en/api/matching' },
        { text: 'Storage', link: '/en/api/storage' },
        { text: 'Dictionary', link: '/en/api/dictionary' },
        { text: 'NVD Integration', link: '/en/api/nvd' },
        { text: 'WFN', link: '/en/api/wfn' },
        { text: 'Validation', link: '/en/api/validation' },
        { text: 'Sets', link: '/en/api/sets' },
        { text: 'Errors', link: '/en/api/errors' }
      ]
    },
    ...moduleGroups('/en/api/modules/')
  ],
  '/en/guide/': [
    {
      text: 'Guide',
      items: [
        { text: 'Overview', link: '/en/guide/' },
        { text: 'Basic Parsing', link: '/en/guide/basic-parsing' },
        { text: 'CPE Matching', link: '/en/guide/matching' },
        { text: 'WFN Conversion', link: '/en/guide/wfn-conversion' },
        { text: 'Version Comparison', link: '/en/guide/version-comparison' },
        { text: 'Applicability Language', link: '/en/guide/applicability' },
        { text: 'CPE Sets', link: '/en/guide/sets' },
        { text: 'Advanced Matching', link: '/en/guide/advanced-matching' },
        { text: 'Storage', link: '/en/guide/storage' },
        { text: 'NVD Integration', link: '/en/guide/nvd-integration' },
        { text: 'CVE Mapping', link: '/en/guide/cve-mapping' }
      ]
    },
    {
      text: 'Feature Guides',
      collapsed: false,
      items: [
        { text: 'SBOM', link: '/en/guide/features/sbom' },
        { text: 'VEX', link: '/en/guide/features/vex' },
        { text: 'Risk Scoring', link: '/en/guide/features/risk-scoring' },
        { text: 'Dependency Graph & Reachability', link: '/en/guide/features/reachability' },
        { text: 'EPSS & KEV', link: '/en/guide/features/epss-kev' },
        { text: 'PURL & Ecosystem', link: '/en/guide/features/purl' },
        { text: 'License Compliance', link: '/en/guide/features/license' },
        { text: 'Manifest to SBOM', link: '/en/guide/features/manifest' },
        { text: 'Export Formats', link: '/en/guide/features/export' }
      ]
    }
  ],
  '/en/cli/': [
    {
      text: 'CLI',
      items: [
        { text: 'Overview', link: '/en/cli/' },
        { text: 'parse', link: '/en/cli/parse' },
        { text: 'match', link: '/en/cli/match' },
        { text: 'search', link: '/en/cli/search' },
        { text: 'dict', link: '/en/cli/dict' },
        { text: 'nvd', link: '/en/cli/nvd' },
        { text: 'cve', link: '/en/cli/cve' },
        { text: 'mcp', link: '/en/cli/mcp' },
        { text: 'version', link: '/en/cli/version' }
      ]
    }
  ],
  '/en/concepts/': [
    {
      text: 'Concepts',
      items: enConcepts
    }
  ],
  '/en/tutorials/': [
    {
      text: 'Tutorials',
      items: enTutorials
    }
  ]
}

const zhSidebar = {
  '/zh/api/': [
    {
      text: 'API 参考',
      items: [
        { text: '概览', link: '/zh/api/' },
        { text: '核心类型', link: '/zh/api/types' },
        { text: '解析功能', link: '/zh/api/parsing' },
        { text: '匹配算法', link: '/zh/api/matching' },
        { text: '存储接口', link: '/zh/api/storage' },
        { text: '字典管理', link: '/zh/api/dictionary' },
        { text: 'NVD集成', link: '/zh/api/nvd' },
        { text: 'WFN格式', link: '/zh/api/wfn' },
        { text: '验证功能', link: '/zh/api/validation' },
        { text: '集合操作', link: '/zh/api/sets' },
        { text: '错误处理', link: '/zh/api/errors' }
      ]
    },
    ...moduleGroups('/zh/api/modules/')
  ],
  '/zh/guide/': [
    {
      text: '使用指南',
      items: [
        { text: '概览', link: '/zh/guide/' },
        { text: '基础解析', link: '/zh/guide/basic-parsing' },
        { text: 'CPE匹配', link: '/zh/guide/matching' },
        { text: 'WFN转换', link: '/zh/guide/wfn-conversion' },
        { text: '版本比较', link: '/zh/guide/version-comparison' },
        { text: '适用性语言', link: '/zh/guide/applicability' },
        { text: 'CPE集合', link: '/zh/guide/sets' },
        { text: '高级匹配', link: '/zh/guide/advanced-matching' },
        { text: '存储操作', link: '/zh/guide/storage' },
        { text: 'NVD集成', link: '/zh/guide/nvd-integration' },
        { text: 'CVE映射', link: '/zh/guide/cve-mapping' }
      ]
    },
    {
      text: '功能指南',
      collapsed: false,
      items: [
        { text: 'SBOM', link: '/zh/guide/features/sbom' },
        { text: 'VEX', link: '/zh/guide/features/vex' },
        { text: '风险评分', link: '/zh/guide/features/risk-scoring' },
        { text: '依赖图与可达性', link: '/zh/guide/features/reachability' },
        { text: 'EPSS 与 KEV', link: '/zh/guide/features/epss-kev' },
        { text: 'PURL 与生态系统', link: '/zh/guide/features/purl' },
        { text: '许可证合规', link: '/zh/guide/features/license' },
        { text: '清单转 SBOM', link: '/zh/guide/features/manifest' },
        { text: '导出格式', link: '/zh/guide/features/export' }
      ]
    }
  ],
  '/zh/cli/': [
    {
      text: '命令行',
      items: [
        { text: '概览', link: '/zh/cli/' },
        { text: 'parse', link: '/zh/cli/parse' },
        { text: 'match', link: '/zh/cli/match' },
        { text: 'search', link: '/zh/cli/search' },
        { text: 'dict', link: '/zh/cli/dict' },
        { text: 'nvd', link: '/zh/cli/nvd' },
        { text: 'cve', link: '/zh/cli/cve' },
        { text: 'mcp', link: '/zh/cli/mcp' },
        { text: 'version', link: '/zh/cli/version' }
      ]
    }
  ],
  '/zh/concepts/': [
    {
      text: '概念',
      items: zhConcepts
    }
  ],
  '/zh/tutorials/': [
    {
      text: '教程',
      items: zhTutorials
    }
  ]
}

export default withMermaid(
  defineConfig({
    title: 'cpe-skills',
    description: 'A comprehensive CPE (Common Platform Enumeration) toolkit for cybersecurity',
    base: '/cpe-skills/',
    cleanUrls: true,

    head: [
      ['link', { rel: 'icon', type: 'image/svg+xml', href: '/cpe-skills/favicon.svg' }]
    ],

    locales: {
      root: {
        label: 'English',
        lang: 'en',
        themeConfig: {
          nav: [
            { text: 'Home', link: '/en/' },
            { text: 'Guide', link: '/en/guide/' },
            { text: 'Concepts', link: '/en/concepts/cpe-overview' },
            { text: 'Tutorials', link: '/en/tutorials/identify-vulnerabilities' },
            { text: 'API', link: '/en/api/' },
            { text: 'CLI', link: '/en/cli/' },
            { text: 'GitHub', link: GITHUB }
          ],
          sidebar: enSidebar
        }
      },
      zh: {
        label: '简体中文',
        lang: 'zh-CN',
        themeConfig: {
          nav: [
            { text: '首页', link: '/zh/' },
            { text: '指南', link: '/zh/guide/' },
            { text: '概念', link: '/zh/concepts/cpe-overview' },
            { text: '教程', link: '/zh/tutorials/identify-vulnerabilities' },
            { text: 'API', link: '/zh/api/' },
            { text: '命令行', link: '/zh/cli/' },
            { text: 'GitHub', link: GITHUB }
          ],
          sidebar: zhSidebar
        }
      }
    },

    themeConfig: {
      socialLinks: [{ icon: 'github', link: GITHUB }],
      footer: {
        message: 'Released under the MIT License.',
        copyright: 'Copyright © 2024-2026 cpe-skills'
      },
      search: {
        provider: 'local'
      }
    },

    mermaid: {
      theme: 'default'
    }
  })
)
