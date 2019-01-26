package pmproxy

import (
	"fmt"
	"sync"
)

// connection amount consumption limiter
type connCons struct {
	Name     string `json:"name"`
	ipAmount *sync.Map
	Limit    uint32 `json:"limit"`
}

func newConnCons(name string, limit uint32) (c *connCons) {
	c = &connCons{
		Name:  name,
		Limit: limit,
	}
	c.ipAmount = new(sync.Map)
	return
}

func (c *connCons) consR() (r *consR) {
	r = &consR{
		open: func(ip string) (ok bool) {
			ok = c.canInc(ip, true)
			return
		},
		can: func(ip string, down int) (ok bool) {
			ok = c.canInc(ip, false)
			return
		},
		update: func(ip string, down int) {
			u, _ := c.ipAmount.Load(ip)
			c.ipAmount.Store(ip, u.(uint32)+1)
		},
		close: func(ip string) {
			u, _ := c.ipAmount.Load(ip)
			c.ipAmount.Store(ip, u.(uint32)-1)
		},
	}
	return
}

const (
	connConsT = "connCons"
)

func (c *connCons) admin(a *AdmCmd, fb fbs,
	fe ferr) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() { fb([]byte(fmt.Sprintf("%d", c.Limit))) },
		},
		{set, func() { c.Limit = a.Limit }},
		{
			show,
			func() {
				v, ok := c.ipAmount.Load(a.RemoteIP)
				if ok {
					fb([]byte(fmt.Sprintf("%d", v)))
				} else {
					fe(NoEntry(a.RemoteIP))
				}
			},
		},
	}
	return
}

const (
	limitK = "limit"
)

func (c *connCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		limitK: c.Limit,
		nameK:  c.Name,
	}
	tỹpe = connConsT
	return
}

func (c *connCons) canInc(ip string,
	increase bool) (ok bool) {
	amount := uint32(0)
	a, b := c.ipAmount.Load(ip)
	if b {
		amount = a.(uint32)
	}
	ok = amount != c.Limit
	if ok && increase {
		amount = amount + 1
		c.ipAmount.Store(ip, amount)
	}
	return
}

func NoEntry(ip string) (e error) {
	e = fmt.Errorf("No entry with key %s", ip)
	return
}

func (c *connCons) fromMap(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				c.Name = stringE(i, fe)
			},
		},
		{
			limitK,
			func(i interface{}) {
				c.Limit = uint32E(i, fe)
			},
		},
	}
	return
}
