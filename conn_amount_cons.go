package pmproxy

import (
	"fmt"
	"github.com/spf13/cast"
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
	r = consR{
		open: func(i ip) (ok bool) {
			ok = c.canInc(i, true)
			return
		},
		can: func(i ip, d download) (ok bool) {
			ok = c.canInc(i, false)
			return
		},
		update: func(i ip, d download) {
			u, _ := c.ipAmount.Load(i)
			c.ipAmount.Store(i, u.(uint32)+1)
		},
		close: func(i ip) {
			u, _ := c.ipAmount.Load(i)
			c.ipAmount.Store(i, u.(uint32)-1)
		},
	}
	return
}

const (
	connConsT = "connCons"
)

func (c *connCons) admin(a *AdmCmd) (bs []byte, e error) {
	kf := []kFunc{
		{
			get,
			func() { bs = []byte(fmt.Sprintf("%d", c.Limit)) },
		},
		{set, func() { c.Limit = a.Limit }},
		{
			show,
			func() {
				v, ok := c.ipAmount.Load(cmd.RemoteIP)
				if ok {
					bs = []byte(fmt.Sprintf("%d", v))
				} else {
					e = NoEntry(cmd.RemoteIP)
				}
			},
		},
	}
	exF(kf, cmd.Cmd, func(d error) { e = d })
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

func (c *connCons) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				c.Name, e = cast.ToStringE(i)
			},
		},
		{
			limitK,
			func(i interface{}) {
				c.Limit, e = cast.ToUint32E(i)
			},
		},
	}
	mapKF(
		kf,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	return
}
