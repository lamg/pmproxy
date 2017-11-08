package pmproxy

import (
	"sync"

	"github.com/lamg/clock"
)

// CMng manages user consumption of quotas
type CMng struct {
	// user_name-uint64
	uc *sync.Map
	qm *QMng
	cl clock.Clock
}

// NewCMng creates a new CMng
func NewCMng(q *QMng, l clock.Clock) (c *CMng) {
	c = &CMng{new(sync.Map), q, l}
	return
}

func (c *CMng) attachInc(r *usrRC) (n *usrCM, e error) {
	n = &usrCM{r, c}
	return
}

// usrCM wraps an *usrRC with a Consumption Manager
type usrCM struct {
	ur *usrRC
	*CMng
}

// Increase could be io.Reader.Read?
func (u *usrCM) Increase(n int) (ok bool) {
	u.ur.rc.tm = u.cl.Now()
	k, t := u.qm.Quota(u.ur)
	ok = t >= 0 && k >= 0
	var r uint64
	if ok {
		m := uint64(float32(n) * k)
		v, _ := u.uc.Load(u.ur.usr.UserName)
		c := v.(uint64)
		r = c + m
		ok = r <= t
	}
	if ok {
		u.uc.Store(u.ur.usr, r)
	}
	return
}
