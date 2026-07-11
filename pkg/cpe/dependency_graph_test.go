package cpeskills

import (
	"testing"
)

func TestDependencyGraph_AddComponent(t *testing.T) {
	g := NewDependencyGraph()

	main := NewSBOMComponent("my-app", "1.0.0")
	main.BomRef = "my-app"
	dep1 := NewSBOMComponent("lodash", "4.17.21")
	dep1.BomRef = "lodash"
	dep2 := NewSBOMComponent("express", "4.17.1")
	dep2.BomRef = "express"

	g.AddComponent(main, []*SBOMComponent{dep1, dep2})

	if g.NodeCount() != 3 {
		t.Errorf("expected 3 nodes, got %d", g.NodeCount())
	}
	if g.EdgeCount() != 2 {
		t.Errorf("expected 2 edges, got %d", g.EdgeCount())
	}

	if node, ok := g.Nodes["my-app"]; !ok || !node.Direct {
		t.Error("my-app should be a direct dependency")
	}
}

func TestDependencyGraph_TopologicalSort(t *testing.T) {
	g := NewDependencyGraph()

	// A → B → C
	g.AddNode(&SBOMComponent{BomRef: "A", Name: "A"})
	g.AddNode(&SBOMComponent{BomRef: "B", Name: "B"})
	g.AddNode(&SBOMComponent{BomRef: "C", Name: "C"})
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")

	sorted, err := g.TopologicalSort()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sorted) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(sorted))
	}

	// 验证顺序: A 应该在 B 之前，B 应该在 C 之前
	pos := make(map[string]int)
	for i, node := range sorted {
		pos[node.ID] = i
	}
	if pos["A"] >= pos["B"] {
		t.Error("A should come before B in topological sort")
	}
	if pos["B"] >= pos["C"] {
		t.Error("B should come before C in topological sort")
	}
}

func TestDependencyGraph_GetDependencyPath(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")
	g.AddEdge("C", "D")

	path, err := g.GetDependencyPath("A", "D")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(path) != 4 {
		t.Errorf("expected path length 4, got %d: %v", len(path), path)
	}

	_, err = g.GetDependencyPath("A", "Z")
	if err == nil {
		t.Error("expected error for nonexistent node")
	}
}

func TestDependencyGraph_SubGraph(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")
	g.AddEdge("A", "D")

	sub := g.SubGraph("A")
	if sub.NodeCount() != 4 {
		t.Errorf("expected 4 nodes in subgraph, got %d", sub.NodeCount())
	}

	sub2 := g.SubGraph("B")
	if sub2.NodeCount() != 2 {
		t.Errorf("expected 2 nodes in B's subgraph, got %d", sub2.NodeCount())
	}
}

func TestDependencyGraph_GetDirectDependencies(t *testing.T) {
	g := NewDependencyGraph()

	main := NewSBOMComponent("app", "1.0")
	main.BomRef = "app"
	dep := NewSBOMComponent("lib", "1.0")
	dep.BomRef = "lib"
	g.AddComponent(main, []*SBOMComponent{dep})

	directDeps := g.GetDirectDependencies()
	if len(directDeps) != 1 {
		t.Errorf("expected 1 direct dep, got %d", len(directDeps))
	}
}

func TestDependencyGraph_GetTransitiveDependencies(t *testing.T) {
	g := NewDependencyGraph()
	g.AddComponent(
		&SBOMComponent{BomRef: "app", Name: "app"},
		[]*SBOMComponent{{BomRef: "lib", Name: "lib"}},
	)

	transitive := g.GetTransitiveDependencies()
	if len(transitive) != 1 {
		t.Errorf("expected 1 transitive dep, got %d", len(transitive))
	}
}

func TestNewDependencyGraph(t *testing.T) {
	g := NewDependencyGraph()
	if g.Nodes == nil {
		t.Error("expected non-nil nodes map")
	}
	if g.Edges == nil {
		t.Error("expected non-nil edges map")
	}
	if g.NodeCount() != 0 {
		t.Errorf("expected 0 nodes, got %d", g.NodeCount())
	}
}

func TestDependencyGraph_GetDependencies(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "B")
	g.AddEdge("A", "C")

	deps := g.GetDependencies("A")
	if len(deps) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(deps))
	}

	// 不存在的节点
	deps = g.GetDependencies("Z")
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for unknown node, got %d", len(deps))
	}
}

func TestDependencyGraph_GetDependents(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "C")
	g.AddEdge("B", "C")

	dependents := g.GetDependents("C")
	if len(dependents) != 2 {
		t.Errorf("expected 2 dependents, got %d", len(dependents))
	}

	// 没有反向依赖的节点
	dependents = g.GetDependents("A")
	if len(dependents) != 0 {
		t.Errorf("expected 0 dependents for A, got %d", len(dependents))
	}
}

func TestDependencyGraph_FindTransitiveVulnerabilities(t *testing.T) {
	g := NewDependencyGraph()

	cpe, _ := Parse("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
	comp := NewSBOMComponent("log4j", "2.14.1")
	comp.SetCPE(cpe)
	comp.BomRef = "log4j"

	g.AddComponent(
		&SBOMComponent{BomRef: "app", Name: "app"},
		[]*SBOMComponent{comp},
	)

	nvdData := &NVDCPEData{
		CPEMatchData: &CPEMatchData{
			CPEToCVEs: map[string][]string{
				"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*": {"CVE-2021-44228"},
			},
		},
	}

	findings := g.FindTransitiveVulnerabilities(nvdData)
	if len(findings) == 0 {
		t.Error("expected at least 1 finding")
	}
}

func TestDependencyGraph_ComputeDepths(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("root", "A")
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")

	g.ComputeDepths()

	if g.Nodes["root"].Depth != 0 {
		t.Errorf("expected root depth 0, got %d", g.Nodes["root"].Depth)
	}
	if g.Nodes["A"].Depth != 1 {
		t.Errorf("expected A depth 1, got %d", g.Nodes["A"].Depth)
	}
	if g.Nodes["B"].Depth != 2 {
		t.Errorf("expected B depth 2, got %d", g.Nodes["B"].Depth)
	}
}

func TestDependencyGraph_TopologicalSort_Cycle(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "B")
	g.AddEdge("B", "C")
	g.AddEdge("C", "A") // 形成环

	_, err := g.TopologicalSort()
	if err == nil {
		t.Error("expected error for cyclic graph")
	}
}

func TestDependencyGraph_GetDependencyPath_NoPath(t *testing.T) {
	g := NewDependencyGraph()
	g.AddEdge("A", "B")
	g.AddEdge("C", "D") // 不连通

	_, err := g.GetDependencyPath("A", "D")
	if err == nil {
		t.Error("expected error for no path")
	}
}

func TestDependencyGraph_AddComponent_NoBomRef(t *testing.T) {
	g := NewDependencyGraph()
	comp := NewSBOMComponent("test", "1.0") // no BomRef set
	dep := NewSBOMComponent("dep", "1.0")
	dep.BomRef = "dep"

	g.AddComponent(comp, []*SBOMComponent{dep})
	if g.NodeCount() != 2 {
		t.Errorf("expected 2 nodes, got %d", g.NodeCount())
	}
}

func TestDependencyGraph_AddNode_Existing(t *testing.T) {
	g := NewDependencyGraph()
	comp := &SBOMComponent{BomRef: "X", Name: "X"}
	g.AddNode(comp)
	g.AddNode(comp) // 重复添加

	if g.NodeCount() != 1 {
		t.Errorf("expected 1 node after duplicate add, got %d", g.NodeCount())
	}
}
