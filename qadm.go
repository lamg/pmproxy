package pmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	rg "regexp"
	"time"

	"github.com/lamg/clock"

	"github.com/lamg/errors"
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

// NameVal name value pair
type NameVal struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
}

// AccExcp represents an access exception
type AccExcp struct {
	// Host name of the forbidden server
	HostR *rg.Regexp `json:"hostR"`
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
	cl clock.Clock
}

// NewQAdm creates a new QAdm instance
func NewQAdm(sm *SMng, gq *QuotaMap, uc *ConsMap,
	al []AccExcp, cl clock.Clock) (q *QAdm) {
	q = &QAdm{
		sm: sm,
		gq: gq,
		uc: uc,
		al: al,
		cl: cl,
	}
	return
}

func (q *QAdm) login(c *credentials,
	addr string) (lr *LogRs, e *errors.Error) {
	lr, e = q.sm.login(c, addr)
	return
}

func (q *QAdm) logout(ip, s string) (e *errors.Error) {
	e = q.sm.logout(ip, s)
	return
}

func (q *QAdm) getQuota(ip string, s string) (r uint64,
	e *errors.Error) {
	var u *User
	u, e = q.sm.userInfo(ip, s)
	if e == nil {
		r, e = q.getUsrQuota(u)
	}
	return
}

func (q *QAdm) getUsrQuota(u *User) (r uint64,
	e *errors.Error) {
	ok := true
	for i := 0; ok && i != len(u.QuotaGroups); i++ {
		var nr uint64
		nr, ok = q.gq.Load(u.QuotaGroups[i])
		if ok {
			r += nr
		}
	}
	return
}

func (q *QAdm) setCons(ip, s string,
	g *NameVal) (e *errors.Error) {
	var u *User
	u, e = q.sm.userInfo(ip, s)
	if e == nil && u.IsAdmin {
		e = q.sm.exists(s, g.Name)
		if e == nil {
			q.uc.Store(g.Name, g.Value)
		}
	} else if e == nil && !u.IsAdmin {
		e = &errors.Error{
			Code: ErrorSQNA,
			Err: fmt.Errorf("%s is not an administrator",
				u.UserName),
		}
	}
	return
}

func (q *QAdm) userCons(ip, s string) (cs uint64,
	e *errors.Error) {
	var c *credentials
	c, e = q.sm.check(ip, s)
	if e == nil {
		cs, _ = q.uc.Load(c.User)
	}
	return
}

func (q *QAdm) cons(uAdr, host string, p int) (y bool) {
	hs, pr, _ := net.SplitHostPort(host)
	ip, _, _ := net.SplitHostPort(uAdr)
	if hs == "" {
		hs = host
	}
	if ip == "" {
		ip = uAdr
	}
	k, cs := q.canReq(ip, hs, pr)
	if cs == nil {
		c := uint64(k * float32(p))
		u, e := q.sm.User(ip)
		y = e == nil
		if y {
			n, _ := q.uc.Load(u.UserName)
			q.uc.Store(u.UserName, n+c)
		}
	}
	return
}

func (q *QAdm) hasQuota(ip string) (y bool) {
	u, e := q.sm.User(ip)
	var cons, quota uint64
	if e == nil {
		cons, _ = q.uc.Load(u.UserName)
		for i := 0; i != len(u.QuotaGroups); i++ {
			r, _ := q.gq.Load(u.QuotaGroups[i])
			quota += r
		}
	}
	y = cons < quota
	return
}

func (q *QAdm) isLogged(ip string) (y bool) {
	_, e := q.sm.User(ip)
	y = e == nil
	return
}

// c < 0 means that the request cannot be made
// c ≥ 0 means c * Response.ContentLength = UserConsumption
// { l is a string with the form host:port }
func (q *QAdm) canReq(ip, host,
	port string) (c float32, cs *CauseCD) {
	d := q.cl.Now()
	var i int
	//f ≡ found l.Host in r.al[].hostname
	var f bool
	i, f, c = 0, false, 1
	for !f && i != len(q.al) {
		f = q.al[i].HostR.MatchString(host)
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
	okPort, restrTime, notLogged, noQuota :=
		(port == "443" || port == "80" || port == ""),
		dailyRestr || intervalRestr,
		!q.isLogged(ip),
		!q.hasQuota(ip)

	if !okPort || notLogged || noQuota || restrTime {
		c, cs = c*-1, new(CauseCD)
	}
	if f && c < 0 {
		cs = &CauseCD{"forbidden site", host}
	} else if !okPort {
		cs = &CauseCD{"forbidden port", port}
	} else if dailyRestr {
		cs = &CauseCD{"daily restriction",
			res.Start.String() + " " + res.End.String()}
	} else if intervalRestr {
		cs = &CauseCD{"time restriction",
			res.Start.String() + " " + res.End.String()}
	} else if notLogged {
		cs = &CauseCD{"not logged", ip}
	} else if noQuota && !f {
		cs = &CauseCD{"no quota", host}
	}
	return
}

// JAccExcp is the AccExcp representation that can be
// [un]marshaled as JSON
type JAccExcp struct {
	HostRE  string    `json:"hostRE"`
	Daily   bool      `json:"daily"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	ConsCfc float32   `json:"consCfc"`
}

// ReadAccExcp reads a []AccExcp serialized as JSON in
// the content of the r io.Reader
func ReadAccExcp(r io.Reader) (l []AccExcp, e *errors.Error) {
	dc, jl := json.NewDecoder(r), make([]JAccExcp, 0)
	ec := dc.Decode(&jl)
	e = errors.NewForwardErr(ec)
	if e == nil {
		l = make([]AccExcp, len(jl))
		for i := 0; e == nil && i != len(l); i++ {
			r, ec := rg.Compile(jl[i].HostRE)
			e = errors.NewForwardErr(ec)
			if e == nil {
				l[i] = AccExcp{r, jl[i].Daily, jl[i].Start, jl[i].End,
					jl[i].ConsCfc}
			}
		}
	}
	if e != nil {
		e.Code = ErrorReadAccExcp
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
