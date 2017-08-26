package main

import (
	"net/url"
	"sync"
	"time"
)

type GroupQuota struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type AccRstr struct {
	hostname   string
	hasIntv    bool
	start, end time.Time
}

type QAdm struct {
	sm *SMng
	// Group Quota and User Consumption
	gq, uc *MapPrs
	al     []AccRstr
}

func (q *QAdm) Init(sm *SMng,
	gq, uc *MapPrs, al []AccRstr) {
	q.sm, q.gq, q.uc, q.al = sm, gq, uc, al
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
		g.Name, e = q.sm.GetGroup(u.Name)
	}
	if e == nil {
		g.Value, _ = q.gq.Load(g.Name)
	}
}

func (q *QAdm) SetQuota(s string, g *GroupQuota) {
	u, e := q.sm.Check(s)
	if e == nil && u.IsAdmin {
		q.gq.Store(g.Name, g.Value)

		// persist
	}
}

func (q *QAdm) UserCons(s string, u *User) {
	l, e := q.sm.Check(s)
	if e == nil && u.Name == "" {
		u.Name = l.Name
	}
	if e == nil {
		u.Cons, _ = q.uc.Load(u.Name)
	}
}

func (q *QAdm) AddCons(u string, c uint64) {
	var ok bool
	var n uint64
	n, ok = q.uc.Load(u)
	if ok {
		q.uc.Store(u, n+c)
	}
	// persist
}

func (q *QAdm) FinishedQuota(u string) (b bool) {
	b = true
	var gr string
	var e error
	gr, e = q.sm.GetGroup(u)
	if e == nil {
		cons, _ = q.uc.Load(u)
		quota, _ = q.gq.Load(gr)
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
