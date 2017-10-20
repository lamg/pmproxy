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
	// ErrorLQ is the error when a quota doesn't appear
	ErrorLQ
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
	// Group Quota
	gq *QuotaMap
	// User Consumption
	uc *ConsMap
	// List of access exceptions
	al []AccExcp
}

// NewQAdm creates a new QAdm instance
func NewQAdm(sm *SMng, gq *QuotaMap, uc *ConsMap,
	al []AccExcp) (q *QAdm) {
	q = &QAdm{
		sm: sm,
		gq: gq,
		uc: uc,
		al: al,
	}
	return
}

func (q *QAdm) login(c *credentials,
	addr string) (u *User, e *errors.Error) {
	u, e = q.sm.login(c, addr)
	return
}

func (q *QAdm) logout(ip string, u *User) (e *errors.Error) {
	e = q.sm.logout(ip, u)
	return
}

func (q *QAdm) getQuota(ip string, u *User) (r uint64,
	e *errors.Error) {
	e = q.sm.check(ip, u)
	println("gq: " + ip)
	if e != nil {
		println(e.Error())
	}
	if e == nil {
		var ok bool
		r, ok = q.gq.Load(u.QuotaGroup)
		if !ok {
			e = &errors.Error{
				Code: ErrorLQ,
				Err: fmt.Errorf("Not found quota for %s",
					u.UserName),
			}
		}
	}
	return
}

func (q *QAdm) setCons(ip string, u *User,
	g *nameVal) (e *errors.Error) {
	e = q.sm.check(ip, u)
	if e == nil && u.IsAdmin {
		q.uc.Store(g.Name, g.Value)
	} else if e == nil && !u.IsAdmin {
		e = &errors.Error{
			Code: ErrorSQNA,
			Err: fmt.Errorf("%s is not an administrator",
				u.UserName),
		}
	}
	return
}

func (q *QAdm) userCons(ip string, u *User) (c uint64,
	e *errors.Error) {
	e = q.sm.check(ip, u)
	var ok bool
	if e == nil {
		c, ok = q.uc.Load(u.UserName)
		if !ok {
			e = &errors.Error{
				Code: ErrorUCLd,
				Err: fmt.Errorf("Not found consupmtion for user %s",
					u.UserName),
			}
		}
	}
	return
}

func (q *QAdm) addCons(ip string, c uint64) {
	u := q.sm.User(ip)
	if u != nil {
		n, _ := q.uc.Load(u.UserName)
		q.uc.Store(u.UserName, n+c)
	}
}

// nlf ≡ not logged ∨ finished quota
func (q *QAdm) nlf(ip string) (b bool) {
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
// c ≥ 0 means c * Response.ContentLength = UserConsumption
// { l is a string with the form host:port }
func (q *QAdm) canReq(ip, host, port string,
	d time.Time) (c float32) {
	var i int
	//f ≡ found l.Host in r.al[].hostname
	var f bool
	i, f, c = 0, false, 1
	for !f && i != len(q.al) {
		f = strings.Contains(host, q.al[i].HostName)
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
	var dailyRestr, intervalRestr bool
	if f {
		dailyRestr, intervalRestr =
			!res.Daily && d.After(res.Start) && d.Before(res.End),
			res.Daily && inDayInterval(d, res.Start, res.End)
	}
	okPort, restrTime :=
		(port == "443" || port == "80" || port == ""),
		dailyRestr || intervalRestr

	if !okPort || q.nlf(ip) || restrTime {
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
