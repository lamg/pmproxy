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
	tỹpe = "groupQuota"
	return
}

func (g *groupQuota) admin() (a admin) {
	a = func(c *AdmCmd) (bs []byte, e error) {
		switch c.Cmd {
		case "get-quota":
			v, ok := g.qts.Load(c.Group)
			if !ok {
				e = NoKey(c.Group)
			} else {
				bs = string(fmt.Sprintf("%v", v))
			}
		case "set-quota":
			g.qts.Store(c.Group, c.Limit)
		case "del-quota":
			g.qts.Delete(c.Group)
		}
		return
	}
	return
}
