package pmproxy

import (
	"fmt"
	"github.com/spf13/cast"
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

func (g *groupQuota) ipQuota() (iq ipQuota) {
	iq = func(i ip) (q uint64) {
		ig := g.ipg(g.IPGroup)
		var grp string
		if ig != nil {
			grp = ig(i)
		}
		if grp != "" {
			v, ok := g.qts.Load(grp)
			if ok {
				q = v.(uint64)
			}
		}
		return
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

func (g *groupQuota) admin(c *AdmCmd) (bs []byte, e error) {
	kf := []kFunc{
		{
			get,
			func() {
				v, ok := g.qts.Load(c.Group)
				if !ok {
					e = NoKey(c.Group)
				} else {
					bs = string(fmt.Sprintf("%v", v))
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
	exF(kf, cmd.Cmd, func(d error) { e = d })
	return
}

func (g *groupQuota) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				g.Name, e = cast.ToStringE(i)
			},
		},
		{
			quotasK,
			func(i interface{}) {
				g.Quotas, e = toStringMapUint64E(i)
			},
		},
	}
	mapKF(
		kf,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
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
