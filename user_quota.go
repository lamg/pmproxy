package pmproxy

import (
	"fmt"
	"sync"
)

type groupQuota struct {
	Name    string            `json: "name"`
	Quotas  map[string]uint64 `json: "quotas"`
	IPGroup string            `json: "ipGroup"`
	ipg     func(string) ipGroup
	qts     *sync.Map
}

const (
	groupQuotaT = "groupQuota"
	quotasK     = "quotas"
)

func (g *groupQuota) init() {
	for k, v := range g.Quotas {
		g.qts.Store(k, v)
	}
}

func (g *groupQuota) ipQuota(ip string) (q uint64) {
	// this could be cached in the session manager
	ig := g.ipg(g.IPGroup)
	var grp []string
	var e error
	if ig != nil {
		grp, e = ig(ip)
	}
	if e == nil {
		inf := func(i int) {
			v, ok := g.qts.Load(grp[i])
			if ok {
				q = q + v.(uint64)
			}
		}
		forall(inf, len(grp))
	}
	return
}

func (g *groupQuota) toSer() (tỹpe string, i interface{}) {
	g.Quotas = make(map[string]uint64)
	g.qts.Range(func(k, v interface{}) (ok bool) {
		g.Quotas[k.(string)], ok = v.(uint64), true
		return
	})
	i = map[string]interface{}{
		nameK:   g.Name,
		quotasK: g.Quotas,
		ipGrpK:  g.IPGroup,
	}
	tỹpe = groupQuotaT
	return
}

func (g *groupQuota) admin(c *AdmCmd, fb fbs,
	fe ferr) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				v, ok := g.qts.Load(c.Group)
				if !ok {
					fe(NoKey(c.Group))
				} else {
					fb([]byte(fmt.Sprintf("%v", v)))
				}
			},
		},
		{
			set,
			func() {
				g.qts.Store(c.Group, c.Limit)
			},
		},
		{
			del,
			func() {
				g.qts.Delete(c.Group)
			},
		},
	}
	return
}

func (g *groupQuota) fromMap(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				g.Name = stringE(i, fe)
			},
		},
		{
			quotasK,
			func(i interface{}) {
				g.Quotas = stringMapUint64E(i, fe)
			},
		},
	}
	return
}

func toStringMapUint64E(i interface{}) (m map[string]uint64,
	e error) {
	m, ok := i.(map[string]uint64)
	if !ok {
		e = fmt.Errorf("Failed cast to map[string]uint64")
	}
	return
}
