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

func (c *connCons) init() {
	c.ipAmount = new(sync.Map)
}

// ConsR implementation

func (c *connCons) Open(ip string) (ok bool) {
	ok = c.canInc(ip, true)
	return
}

func (c *connCons) Can(ip string, n int) (ok bool) {
	ok = c.canInc(ip, false)
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

func (c *connCons) UpdateCons(ip string, n int) {
	u, _ := c.ipAmount.Load(ip)
	c.ipAmount.Store(ip, u.(uint32)+1)
}

func (c *connCons) Close(ip string) {
	u, _ := c.ipAmount.Load(ip)
	c.ipAmount.Store(ip, u.(uint32)-1)
}

func (c *connCons) Name() (r string) {
	r = c.NameF
	return
}

// end

// Admin implementation

func (c *connCons) Exec(cmd *AdmCmd) (r string, e error) {
	if cmd.Cmd == "show" {
		v, ok := c.ipAmount.Load(cmd.RemoteIP)
		if ok {
			r = fmt.Sprintf("%d", v)
		} else {
			e = NoEntry(cmd.RemoteIP)
		}
	} else {
		e = NoCmd(cmd.Cmd)
	}
	return
}

func NoEntry(ip string) (e error) {
	e = fmt.Errorf("No entry with key %s", ip)
	return
}

// end
