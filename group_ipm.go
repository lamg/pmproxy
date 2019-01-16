package pmproxy

import (
	"sync"
)

type groupIPM struct {
	Name  string `json:"name"`
	Group string `json: "group"`
	IPGrp string `json: "ipGrp"`
	ipGS  func(string) (ipGrp, bool)
}

type ipGrp func(ip) ([]string, error)

func (g *groupIPM) manager() (m *manager) {
	m = &manager{
		name: g.Name,
		cons: idCons,
		adm: func(c *AdmCmd) (bs []byte, e error) {
			switch c.Cmd {
			case "set-group":
				g.Group = c.Group
			case "get-group":
				bs = []byte(g.Group)
			case "set-ipGrp":
				g.IPGrp = c.MngName
			case "get-ipGrp":
				bs = []byte(g.IPGrp)
			default:
				e = NoCmd(c.Cmd)
			}
			return
		},
		mtch: func(i ip) (ok bool) {
			ig, ok := g.ipGS(g.IPGrp)
			var gs []string
			if ok {
				gs, e := ig(ip)
				ok = e == nil
			}
			if ok {
				ib := func(i int) (b bool) {
					b = gs[i] == g.Group
					return
				}
				ok, _ = bLnSrch(ib, len(gs))
			}
			return
		},
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK:  g.Name,
				groupK: g.Group,
				ipGrpK: g.IPGrp,
			}
			return
		},
	}
	return
}
