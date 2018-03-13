package pmproxy

type RDGraph struct {
	Nodes    []ResDet   `json:"nodes"`
	AdjLs    [][]uint32 `json:"adjLs"`
	NodesOrd []uint32   `json:"nodesOrd"`
}

func (g *RDGraph) Persist() (e error) {

	return
}
