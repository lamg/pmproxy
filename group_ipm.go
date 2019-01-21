package pmproxy

type groupIPM struct {
	Name  string `json:"name"`
	Group string `json: "group"`
	IPGrp string `json: "ipGrp"`
	ipGS  func(string) ipGrp
}

type ipGrp func(ip) ([]string, error)

func (g *groupIPM) admin(c *AdmCmd) (bs []byte, e error) {
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
}

func (g *groupIPM) match(i ip) (ok bool) {
	gs, e := g.ipGS(g.IPGrp)(i)
	if e == nil {
		ib := func(i int) (b bool) {
			b = gs[i] == g.Group
			return
		}
		ok, _ = bLnSrch(ib, len(gs))
	}
	return
}

func (g *groupIPM) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:  g.Name,
		groupK: g.Group,
		ipGrpK: g.IPGrp,
	}
	tỹpe = "groupIPM"
	return
}
