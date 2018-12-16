package pmproxy

import (
	"fmt"
	"sync"
)

type usrQt func(string) uint64
type usrQtSer func() *usrQtS
type usrQtS struct {
	Name   string            `json: "name" toml: "name"`
	Quotas map[string]uint64 `json: "quotas" toml: "quotas"`
	UsrGrp string            `json: "usrGrp" toml: "usrGrp"`
}

func newUsrQt(name string, qs map[string]uint64,
	ug usrGrp) (u usrQt, qa qtAdm, ts usrQtSer) {
	var qsc *sync.Map
	for k, v := range qs {
		qsc.Store(k, v)
	}
	u = func(usr string) (r uint64) {
		gs := ug(usr)
		r = 0
		for _, j := range gs {
			v, ok := qsc.Load(j)
			if ok {
				r = r + v.(uint64)
			}
		}
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
