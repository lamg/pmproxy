package pmproxy

import (
	"net/url"
	"sync"
	"time"
)

type GroupQuota struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type Access struct {
	hostname   string
	hasIntv    bool
	start, end time.Time
}

type QAdm struct {
	sm SessionManager
	ug UserGroup
	// Group Quota and User Consumption
	gq, uc *sync.Map
	al     []Access
}

func (q *QAdm) Init(sm SessionManager, ug UserGroup,
	gq, uc *sync.Map) {
	//TODO initialize al
	q.sm, q.ug, q.gq, q.uc = sm, ug, gq, uc
}

func (q *QAdm) Login(c *Credentials,
	a string) (s string, e error) {
	s, e = q.sm.Login(c, a)
	return
}

func (q *QAdm) Logout(s string) (e error) {
	e = q.sm.Logout(s)
	return
}

func (q *QAdm) GetQuota(s string, g *GroupQuota) {
	u, e := q.sm.Check(s)
	if e == nil && g.Name == "" {
		// get group for s
		g.Name, _ = q.ug.GetGroup(u.Name)
	}
	if e == nil {
		var v interface{}
		v, _ = q.gq.Load(g.Name)
		g.Value = v.(uint64)
	}
}

func (q *QAdm) SetQuota(s string, g *GroupQuota) {
	u, e := q.sm.Check(s)
	if e == nil && u.IsAdmin {
		q.gq.Store(g.Name, g.Value)
	}
}

func (q *QAdm) UserCons(s string, u *User) {
	l, e := q.sm.Check(s)
	if e == nil && u.Name == "" {
		u.Name = l.Name
	}
	if e == nil {
		var v interface{}
		var ok bool
		v, ok = q.uc.Load(u.Name)
		if ok {
			u.Cons = v.(uint64)
		}
	}
}

func (q *QAdm) FinishedQuota(u string) (b bool) {
	b = true
	var gr string
	var e error
	gr, e = q.ug.GetGroup(u)
	if e == nil {
		var ic, iq interface{}
		var okc, okq bool
		ic, okc = q.uc.Load(u)
		iq, okq = q.gq.Load(gr)
		var cons, quota uint64
		if okc {
			cons = ic.(uint64)
		}
		if okq {
			quota = iq.(uint64)
		}
		b = cons >= quota
	}
	return
}

func (r *QAdm) CanReq(ip string, l *url.URL,
	d time.Time) (b bool) {
	var u string
	u = r.sm.UserName(ip)
	var i int
	i, b = 0, !r.FinishedQuota(u)
	// b = not finished quota and not forbidden url and if has
	//     forbidden interval it is outside of it
	for b && i != len(r.al) {
		i, b = i+1, r.al[i].hostname != l.Host &&
			(!r.al[i].hasIntv || !(d.After(r.al[i].start) &&
				d.Before(r.al[i].end)))
	}
	return
}
