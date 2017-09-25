package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"io"
	"strings"
	"time"
)

const (
	// ErrorReadAccExcp is the error returned by ReadAccExcp
	ErrorReadAccExcp = iota
	// ErrorUCLd is the error when loading a key at userCons call
	ErrorUCLd
	// ErrorSQNA is the error when setting a quota without being
	// administrator, at setQuota call
	ErrorSQNA
	// ErrorMalformedRecord is the error returned when a record
	// hasn't the required format
	ErrorMalformedRecord
)

type nameVal struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// AccExcp represents an access exception
type AccExcp struct {
	// Host name of the forbidden server
	HostName string `json:"hostName"`
	// The restriction is applied daily, this means that
	// only the time of the day is looked for restricting
	// access
	Daily bool `json:"daily"`
	// Time when the restriction starts
	Start time.Time `json:"start"`
	// Time when the restriction ends
	End time.Time `json:"end"`
	// Coeficient for multiplying the ContentLength and
	// recording the result as downloaded amount
	ConsCfc float32 `json:"consCfc"`
}

// QAdm is the administrator of quotas, also restricts
// downloads according an []AccExcp and handles users's
// sessions through an *SMng
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

// NewQAdm creates a new QAdm instance
func NewQAdm(sm *SMng, gq, uc *MapPrs, al []AccExcp,
	rd time.Time, cd time.Duration) (q *QAdm) {
	q = &QAdm{
		sm: sm,
		gq: gq,
		uc: uc,
		al: al,
		rd: rd,
		cd: cd,
	}
	return
}

func (q *QAdm) login(c *credentials,
	addr string) (s string, e *errors.Error) {
	s, e = q.sm.login(c, addr)
	return
}

func (q *QAdm) logout(ip, s string) (e *errors.Error) {
	e = q.sm.logout(ip, s)
	return
}

func (q *QAdm) getQuota(ip, s string, g *nameVal) {
	u, e := q.sm.check(ip, s)
	if e == nil {
		if g.Name == "" {
			g.Name = u.QuotaGroup
		}
		g.Value, _ = q.gq.load(g.Name)
	}
}

func (q *QAdm) setQuota(ip, s string,
	g *nameVal) (e *errors.Error) {
	var u *User
	u, e = q.sm.check(ip, s)
	if e == nil && u.IsAdmin {
		q.gq.store(g.Name, g.Value)
		_, e = q.gq.persistIfTime()
	} else if e == nil && !u.IsAdmin {
		e = &errors.Error{
			Code: ErrorSQNA,
			Err:  fmt.Errorf("%s is not an administrator", u.UserName),
		}
	}
	return
}

func (q *QAdm) userCons(ip, s string,
	nv *nameVal) (e *errors.Error) {
	var u *User
	u, e = q.sm.check(ip, s)
	if nv.Name == "" {
		nv.Name = u.UserName
	}
	var ok bool
	if e == nil {
		nv.Value, ok = q.uc.load(nv.Name)
	}
	if !ok {
		e = &errors.Error{
			Code: ErrorUCLd,
			Err: fmt.Errorf("Not found consupmtion for user %s",
				nv.Name),
		}
	}
	return
}

func (q *QAdm) addCons(ip string, c uint64) {
	// reset consumption if cycle ended
	var nt time.Time
	nt = newTime(q.rd, q.cd)
	if !nt.Equal(q.rd) {
		q.uc.reset()
		q.rd = nt
	}

	u := q.sm.User(ip)
	fmt.Printf("IP: %s User: %v Cons: %d\n", ip, u, c)
	if u != nil {
		n, _ := q.uc.load(u.UserName)
		q.uc.store(u.UserName, n+c)
		q.uc.persistIfTime()
	}
}

// nlf ≡ not logged ∨ finished quota
func (q *QAdm) nlf(ip string) (b bool) {
	var u *User
	u = q.sm.User(ip)
	var cons, quota uint64
	if u != nil {
		cons, _ = q.uc.load(u.UserName)
		quota, _ = q.gq.load(u.QuotaGroup)
	}
	b = cons >= quota
	return
}

// c < 0 means that the request cannot be made
// c ≥ 0 means c * Response.ContentLength = UserConsumption
// { l is a string with the form host:port }
func (q *QAdm) canReq(ip string, l string,
	d time.Time) (c float32) {

	var i int
	//f ≡ found l.Host in r.al[].hostname
	var f bool
	i, f, c = 0, false, 1
	for !f && i != len(q.al) {
		f = strings.Contains(l, q.al[i].HostName)
		if !f {
			i = i + 1
		}
	}
	var res AccExcp
	if f {
		res = q.al[i]
		c = res.ConsCfc
	}
	// { c ≥ 0 }
	if q.nlf(ip) || (f &&
		((!res.Daily && d.After(res.Start) && d.Before(res.End)) ||
			(res.Daily && inDayInterval(d, res.Start, res.End)))) {
		c = c * -1
	}
	//{ q.nlf(ip) ∨ d inside forbidden interval ⇒ c < 0 }
	return
}

// ReadAccExcp reads a []AccExcp serialized as JSON in
// the content of the r io.Reader
func ReadAccExcp(r io.Reader) (l []AccExcp, e *errors.Error) {
	var dc *json.Decoder
	dc, l = json.NewDecoder(r), make([]AccExcp, 0)
	ec := dc.Decode(&l)
	if ec != nil {
		e = &errors.Error{
			Code: ErrorReadAccExcp,
			Err:  ec,
		}
	}
	return
}

// a ∈ (x, y)
func inDayInterval(a, x, y time.Time) (b bool) {
	var beforeY, afterX bool
	beforeY = beforeInDay(a, y)
	afterX = beforeInDay(x, a)
	b = beforeY && afterX
	return
}

func beforeInDay(x, y time.Time) (b bool) {
	b = x.Hour() < y.Hour() || x.Minute() < y.Minute() ||
		x.Second() < y.Second() || x.Nanosecond() < y.Nanosecond()
	return
}
