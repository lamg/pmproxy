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

type ipGroup func(ip) ([]string, error)
type ipQuota func(ip) uint64

func (g *groupQuota) manager() (m *manager, iq ipQuota) {
	m = &manager{
		name: g.Name,
		tỹpe: "groupQuota",
		cons: idConsR,
		mtch: idMatch,
		adm: func(c *AdmCmd) (bs []byte, e error) {
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
		},
		toSer: func() (i interface{}) {
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
			returnX
		},
	}
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

func newUsrQt(name string, qs map[string]uint64,
	ug usrGrp) (u usrQt, qa qtAdm, ts usrQtSer) {
	var qsc *sync.Map
	for k, v := range qs {
		qsc.Store(k, v)
	}
	u = func(usr string) (r uint64) {
		gs := ug(usr)
		inf := func(i int) {
			v, ok := qsc.Load(gs[i])
			if ok {
				r = r + v.(uint64)
			}
		}
		forall(inf, len(gs))
		return
	}

	qa = func(usr, grp, sGrp, dGrp bool, user, group string,
		quota uint64) (r string, e error) {
		if usr {
			q := u(user)
			r = fmt.Sprintf("%d", q)
		} else if grp {
			v, ok := qsc.Load(group)
			if ok {
				r = fmt.Sprintf("%d", v)
			} else {
				e = NoEntry(group)
			}
		} else if sGrp {
			qsc.Store(group, quota)
		} else if dGrp {
			qsc.Delete(group)
		}
		return
	}

	ts = func() (st *usrQtS) {
		st = &usrQtS{
			Name:   name,
			Quotas: make(map[string]uint64),
		}
		qsc.Range(func(k, v interface{}) (ok bool) {
			ks, vu := k.(string), v.(uint64)
			st.Quotas[ks] = vu
			ok = true
			return
		})
		return
	}
	return
}

type qtAdm func(bool, bool, bool, bool, string, string,
	uint64) (string, error)
