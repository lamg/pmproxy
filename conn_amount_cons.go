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

func (c *connCons) consR() (c *consR) {
	c = consR{
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

func (c *connCons) admin(a *AdmCmd) (bs []byte, e error) {
	switch a.Cmd {
	case "get-limit":
		bs = []byte(fmt.Sprintf("%d", c.Limit))
	case "set-limit":
		c.Limit = a.Limit
	case "show":
		v, ok := c.ipAmount.Load(cmd.RemoteIP)
		if ok {
			bs = []byte(fmt.Sprintf("%d", v))
		} else {
			e = NoEntry(cmd.RemoteIP)
		}
	default:
		e = NoCmd(c.Cmd)
	}
	return
}

func (c *connCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		limitK: c.Limit,
		nameK:  c.Name,
	}
	tỹpe = "connCons"
	return
}

func (c *connCons) canInc(ip string, increase bool) (ok bool) {
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
	m, e := cast.ToStringMapE(i)
	me := func(f func(interface{})) (fk func(string)) {
		fk = mpErr(m, func(d error) { e = d }, f)
		return
	}
	return
}
