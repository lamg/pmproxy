package pmproxy

type groupIPM struct {
	Name  string `json:"name"`
	Group string `json: "group"`
	IPGrp string `json: "ipGrp"`
	ipGS  func(string) ipGroup
}

const (
	ipGrpK = "ipGrp"
	groupK = "group"
)

func (g *groupIPM) admin(c *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	if c.IsAdmin {
		cs = []cmdProp{
			{
				cmd:  set,
				prop: groupK,
				f:    func() { g.Group = c.Group },
			},
			{
				cmd:  get,
				prop: groupK,
				f:    func() { fb([]byte(g.Group)) },
			},
			{
				cmd:  set,
				prop: ipGrpK,
				f:    func() { g.IPGrp = c.MngName },
			},
			{
				cmd:  get,
				prop: ipGrpK,
				f:    func() { fb([]byte(g.IPGrp)) },
			},
		}
	}
	return
}

func (g *groupIPM) match(ip string) (ok bool) {
	gs, e := g.ipGS(g.IPGrp)(ip)
	if e == nil {
		ib := func(i int) (b bool) {
			b = gs[i] == g.Group
			return
		}
		ok, _ = bLnSrch(ib, len(gs))
	}
	return
}

const (
	groupIPMT = "groupIPM"
)

func (g *groupIPM) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:  g.Name,
		groupK: g.Group,
		ipGrpK: g.IPGrp,
	}
	tỹpe = groupIPMT
	return
}

func (g *groupIPM) fromMapKF(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				g.Name = stringE(i, fe)
			},
		},
		{
			groupK,
			func(i interface{}) {
				g.Group = stringE(i, fe)
			},
		},
		{
			ipGrpK,
			func(i interface{}) {
				g.IPGrp = stringE(i, fe)
			},
		},
	}
	return
}
