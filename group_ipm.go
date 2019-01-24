package pmproxy

type groupIPM struct {
	Name  string `json:"name"`
	Group string `json: "group"`
	IPGrp string `json: "ipGrp"`
	ipGS  func(string) ipGroup
}

const (
	setGroup = "setGroup"
	getGroup = "getGroup"
	setIPGrp = "setIPGrp"
	getIPGrp = "getIPGrp"
	ipGrpK   = "ipGrp"
	groupK   = "group"
)

func (g *groupIPM) admin(c *AdmCmd) (bs []byte, e error) {
	if c.IsAdmin {
		switch c.Cmd {
		case setGroup:
			g.Group = c.Group
		case getGroup:
			bs = []byte(g.Group)
		case setIPGrp:
			g.IPGrp = c.MngName
		case getIPGrp:
			bs = []byte(g.IPGrp)
		default:
			e = NoCmd(c.Cmd)
		}
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

func (g *groupIPM) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				g.Name, e = cast.ToStringE(i)
			},
		},
		{
			groupK,
			func(i interface{}) {
				g.Group, e = cast.ToStringE(i)
			},
		},
		{
			ipGrpK,
			func(i interface{}) {
				g.ipGrp, e = cast.ToStringE(i)
			},
		},
	}
	mapKF(
		fe,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	return
}
