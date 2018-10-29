package pmproxy

import "sync"

// connection amount consumption limiter
type connCons struct {
	ipAmount *sync.Map
	limit    uint32
}

func (c *connCons) Can(ip string, n int) (ok bool) {
	amount := uint32(0)
	a, b := c.ipAmount.LoadOrStore(ip, amount)
	if b {
		amount = a.(uint32)
	}
	ok = amount != c.limit
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
