package cpeskills

import (
	"fmt"
	"sort"
)

// DependencyGraph 表示组件依赖关系图
//
// 用于建模软件组件之间的依赖关系，支持传递性漏洞分析和可达性判断。
// 使用邻接表实现，节点通过唯一 ID 标识。
type DependencyGraph struct {
	// Nodes 图中的所有节点 (nodeID → node)
	Nodes map[string]*DependencyNode `json:"nodes"`

	// Edges 边: nodeID → 依赖的 nodeID 列表
	Edges map[string][]string `json:"edges"`
}

// DependencyNode 表示依赖图中的一个节点
type DependencyNode struct {
	// ID 节点唯一标识符
	ID string `json:"id"`

	// Component 关联的 SBOM 组件
	Component *SBOMComponent `json:"component"`

	// Depth 在依赖树中的深度 (0 = 直接依赖)
	Depth int `json:"depth"`

	// Direct 是否为直接依赖
	Direct bool `json:"direct"`
}

// NewDependencyGraph 创建一个新的依赖关系图
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		Nodes: make(map[string]*DependencyNode),
		Edges: make(map[string][]string),
	}
}

// AddComponent 向图中添加一个组件及其依赖
func (g *DependencyGraph) AddComponent(component *SBOMComponent, dependencies []*SBOMComponent) {
	nodeID := component.BomRef
	if nodeID == "" {
		nodeID = generateBomRef(component)
	}

	// 添加节点
	if _, exists := g.Nodes[nodeID]; !exists {
		g.Nodes[nodeID] = &DependencyNode{
			ID:        nodeID,
			Component: component,
			Depth:     0,
			Direct:    true,
		}
	}

	// 添加依赖边
	depIDs := make([]string, 0, len(dependencies))
	for _, dep := range dependencies {
		depID := dep.BomRef
		if depID == "" {
			depID = generateBomRef(dep)
		}

		// 添加依赖节点
		if _, exists := g.Nodes[depID]; !exists {
			g.Nodes[depID] = &DependencyNode{
				ID:        depID,
				Component: dep,
				Depth:     1,
				Direct:    false,
			}
		}

		depIDs = append(depIDs, depID)
	}

	g.Edges[nodeID] = depIDs
}

// AddNode 添加一个独立节点
func (g *DependencyGraph) AddNode(component *SBOMComponent) {
	nodeID := component.BomRef
	if nodeID == "" {
		nodeID = generateBomRef(component)
	}
	if _, exists := g.Nodes[nodeID]; !exists {
		g.Nodes[nodeID] = &DependencyNode{
			ID:        nodeID,
			Component: component,
			Direct:    true,
		}
	}
}

// AddEdge 添加一条依赖边
func (g *DependencyGraph) AddEdge(from, to string) {
	// 确保两个节点都存在
	if _, ok := g.Nodes[from]; !ok {
		g.Nodes[from] = &DependencyNode{ID: from, Direct: true}
	}
	if _, ok := g.Nodes[to]; !ok {
		g.Nodes[to] = &DependencyNode{ID: to, Direct: false}
	}

	g.Edges[from] = append(g.Edges[from], to)
}

// GetDependencies 获取节点的直接依赖
func (g *DependencyGraph) GetDependencies(nodeID string) []*DependencyNode {
	depIDs, ok := g.Edges[nodeID]
	if !ok {
		return nil
	}
	result := make([]*DependencyNode, 0, len(depIDs))
	for _, id := range depIDs {
		if node, ok := g.Nodes[id]; ok {
			result = append(result, node)
		}
	}
	return result
}

// GetDependents 获取依赖此节点的节点（反向依赖）
func (g *DependencyGraph) GetDependents(nodeID string) []*DependencyNode {
	var result []*DependencyNode
	for fromID, depIDs := range g.Edges {
		for _, toID := range depIDs {
			if toID == nodeID {
				if node, ok := g.Nodes[fromID]; ok {
					result = append(result, node)
				}
				break
			}
		}
	}
	return result
}

// GetDependencyPath 查找从 from 到 to 的依赖路径
func (g *DependencyGraph) GetDependencyPath(from, to string) ([]string, error) {
	if _, ok := g.Nodes[from]; !ok {
		return nil, fmt.Errorf("node %s not found", from)
	}
	if _, ok := g.Nodes[to]; !ok {
		return nil, fmt.Errorf("node %s not found", to)
	}

	visited := make(map[string]bool)
	parent := make(map[string]string)
	queue := []string{from}
	visited[from] = true

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if current == to {
			// 重建路径
			path := []string{to}
			for p := parent[to]; p != from; p = parent[p] {
				path = append([]string{p}, path...)
			}
			path = append([]string{from}, path...)
			return path, nil
		}

		for _, depID := range g.Edges[current] {
			if !visited[depID] {
				visited[depID] = true
				parent[depID] = current
				queue = append(queue, depID)
			}
		}
	}

	return nil, fmt.Errorf("no path from %s to %s", from, to)
}

// TopologicalSort 拓扑排序
func (g *DependencyGraph) TopologicalSort() ([]*DependencyNode, error) {
	// 计算入度
	inDegree := make(map[string]int)
	for nodeID := range g.Nodes {
		inDegree[nodeID] = 0
	}
	for _, depIDs := range g.Edges {
		for _, depID := range depIDs {
			inDegree[depID]++
		}
	}

	// 入度为 0 的节点入队
	queue := make([]string, 0)
	for nodeID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, nodeID)
		}
	}

	var result []*DependencyNode
	for len(queue) > 0 {
		nodeID := queue[0]
		queue = queue[1:]

		if node, ok := g.Nodes[nodeID]; ok {
			result = append(result, node)
		}

		for _, depID := range g.Edges[nodeID] {
			inDegree[depID]--
			if inDegree[depID] == 0 {
				queue = append(queue, depID)
			}
		}
	}

	if len(result) != len(g.Nodes) {
		return nil, fmt.Errorf("graph contains a cycle")
	}

	return result, nil
}

// SubGraph 提取以 rootID 为根的子图
func (g *DependencyGraph) SubGraph(rootID string) *DependencyGraph {
	sub := NewDependencyGraph()

	visited := make(map[string]bool)
	var dfs func(nodeID string)
	dfs = func(nodeID string) {
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true

		if node, ok := g.Nodes[nodeID]; ok {
			sub.Nodes[nodeID] = node
		}

		for _, depID := range g.Edges[nodeID] {
			sub.Edges[nodeID] = append(sub.Edges[nodeID], depID)
			dfs(depID)
		}
	}

	dfs(rootID)
	return sub
}

// FindTransitiveVulnerabilities 查找传递性漏洞
//
// 遍历依赖图，查找所有受漏洞影响的组件（包括传递性依赖）。
func (g *DependencyGraph) FindTransitiveVulnerabilities(cveData *NVDCPEData) []*VulnerabilityFinding {
	var findings []*VulnerabilityFinding

	for _, node := range g.Nodes {
		if node.Component == nil || node.Component.CPE == nil {
			continue
		}

		cves := cveData.FindCVEsForCPE(node.Component.CPE)
		for _, cveID := range cves {
			finding := NewVulnerabilityFinding()
			finding.CVE = &CVEReference{CVEID: cveID}
			if node.Direct {
				finding.Reachability = "direct"
			} else {
				finding.Reachability = "transitive"
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// NodeCount 返回图中节点数量
func (g *DependencyGraph) NodeCount() int {
	return len(g.Nodes)
}

// EdgeCount 返回图中边数量
func (g *DependencyGraph) EdgeCount() int {
	count := 0
	for _, deps := range g.Edges {
		count += len(deps)
	}
	return count
}

// GetDirectDependencies 获取所有直接依赖
func (g *DependencyGraph) GetDirectDependencies() []*DependencyNode {
	var result []*DependencyNode
	for _, node := range g.Nodes {
		if node.Direct {
			result = append(result, node)
		}
	}
	// 按深度排序
	sort.Slice(result, func(i, j int) bool {
		return result[i].Depth < result[j].Depth
	})
	return result
}

// GetTransitiveDependencies 获取所有传递性依赖
func (g *DependencyGraph) GetTransitiveDependencies() []*DependencyNode {
	var result []*DependencyNode
	for _, node := range g.Nodes {
		if !node.Direct {
			result = append(result, node)
		}
	}
	return result
}

// ComputeDepths 计算所有节点的深度
func (g *DependencyGraph) ComputeDepths() {
	// 找到所有根节点（没有入边的节点）
	isRoot := make(map[string]bool)
	for nodeID := range g.Nodes {
		isRoot[nodeID] = true
	}
	for _, depIDs := range g.Edges {
		for _, depID := range depIDs {
			isRoot[depID] = false
		}
	}

	// BFS 从根节点开始计算深度
	for nodeID := range isRoot {
		if isRoot[nodeID] {
			g.bfsDepth(nodeID)
		}
	}
}

// bfsDepth BFS 计算深度
func (g *DependencyGraph) bfsDepth(rootID string) {
	visited := make(map[string]bool)
	queue := []string{rootID}
	visited[rootID] = true

	if node, ok := g.Nodes[rootID]; ok {
		node.Depth = 0
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentDepth := 0
		if node, ok := g.Nodes[current]; ok {
			currentDepth = node.Depth
		}

		for _, depID := range g.Edges[current] {
			if !visited[depID] {
				visited[depID] = true
				if node, ok := g.Nodes[depID]; ok {
					node.Depth = currentDepth + 1
				}
				queue = append(queue, depID)
			}
		}
	}
}
