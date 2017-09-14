package pmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"
)

type NameVal struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

type AccExcp struct {
	HostName string    `json:"hostName"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	ConsCfc  float32   `json:"consCfc"`
}

type QAdm struct {
	sm *SMng
	// Group Quota and User Consumption
	gq, uc *MapPrs
	al     []AccExcp
	// Consumption reset date
	rd time.Time
	// Consumption cycle duration
	cd time.Duration
}

func (q *QAdm) Init(sm *SMng, gq, uc *MapPrs, al []AccExcp,
	rd time.Time, cd time.Duration) {
	q.sm, q.gq, q.uc, q.al, q.rd, q.cd = sm, gq, uc, al, rd, cd
}

func (q *QAdm) Login(c *Credentials,
	addr string) (s string, e error) {
	s, e = q.sm.Login(c, addr)
	return
}

func (q *QAdm) Logout(ip, s string) (e error) {
	e = q.sm.Logout(ip, s)
	return
}

func (q *QAdm) GetQuota(ip, s string, g *NameVal) {
	_, e := q.sm.Check(ip, s)
	if e == nil {
		g.Value, _ = q.gq.Load(g.Name)
	}
}

func (q *QAdm) SetQuota(ip, s string, g *NameVal) (e error) {
	var u *User
	u, e = q.sm.Check(ip, s)
	if e == nil && u.IsAdmin {
		q.gq.Store(g.Name, g.Value)
		_, e = q.gq.PersistIfTime()
	} else if e == nil && !u.IsAdmin {
		e = fmt.Errorf("%s is not an administrator", u.UserName)
	}
	return
}

func (q *QAdm) UserCons(ip, s, usr string) (v uint64, e error) {
	_, e = q.sm.Check(ip, s)
	var ok bool
	if e == nil {
		v, ok = q.uc.Load(usr)
	}
	if !ok {
		e = fmt.Errorf("Not found consupmtion for user %s", usr)
	}
	return
}

func (q *QAdm) AddCons(ip string, c uint64) {
	// reset consumption if cycle ended
	var nt time.Time
	nt = newTime(q.rd, q.cd)
	if nt != q.rd {
		q.uc.Reset()
		q.rd = nt
	}

	var n uint64
	var u *User
	u = q.sm.User(ip)
	if u != nil {
		n, _ = q.uc.Load(u.UserName)
		q.uc.Store(u.UserName, n+c)
		q.uc.PersistIfTime()
	}
}

func (q *QAdm) FinishedQuota(ip string) (b bool) {
	var u *User
	u = q.sm.User(ip)
	var cons, quota uint64
	if u != nil {
		cons, _ = q.uc.Load(u.UserName)
		quota, _ = q.gq.Load(u.QuotaGroup)
	}
	b = cons >= quota
	return
}

// c < 0 means that the request cannot be made
// c >= 0 means c * Response.ContentLength = UserConsumption
func (r *QAdm) CanReq(ip string, l *url.URL,
	d time.Time) (c float32) {
	var i int
	//f means found l.Host in r.al[].hostname
	var f bool
	i, f, c = 0, false, 1
	for !f && i != len(r.al) {
		f = r.al[i].HostName == l.Host
		if !f {
			i = i + 1
		}
	}
	if f {
		c = r.al[i].ConsCfc
	}
	if c != -1 && (r.FinishedQuota(ip) ||
		(d.After(r.al[i].Start) &&
			d.Before(r.al[i].End))) {
		c = c * -1
	}
	return
}

func ReadAccExcp(r io.Reader) (l []AccExcp, e error) {
	var dc *json.Decoder
	dc, l = json.NewDecoder(r), make([]AccExcp, 0)
	e = dc.Decode(&l)
	return
}
