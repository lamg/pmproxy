package pmproxy

import (
	"fmt"
	"sync"
)

type usrQt func(string) uint64
type usrQtSer func() *usrQtS
type usrQtS struct {
	Name   string            `toml: "name"`
	Quotas map[string]uint64 `toml: "quotas"`
}

func newUsrQt(name string, qs map[string]uint64,
	ug usrGrp) (u usrQt, a Admin, ts usrQtSer) {
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
	qa := func(cmd *AdmCmd) (r string, e error) {
		switch cmd.Cmd {
		case "user":
			q := u(cmd.User)
			r = fmt.Sprintf("%d", q)
		case "group":
			v, ok := qsc.Load(cmd.Group)
			if ok {
				r = fmt.Sprintf("%d", v)
			} else {
				e = NoEntry(cmd.Group)
			}
		case "set-group":
			qsc.Store(cmd.Group, cmd.Limit)
		case "del-group":
			qsc.Delete(cmd.Group)
		}
		return
	}
	a = &qtAdmImp{qa: qa}
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

type qtAdm func(*AdmCmd) (string, error)

type qtAdmImp struct {
	qa qtAdm
}

func (q *qtAdmImp) Exec(cmd *AdmCmd) (r string, e error) {
	r, e = q.qa(cmd)
	return
}
