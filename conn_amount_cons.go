package pmproxy

import "sync"

// connection amount consumption limiter
type connCons struct {
	name     string
	ipAmount *sync.Map
	limit    uint32
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
	ok = amount != c.limit
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

// end

// Admin implementation

func (c *connCons) Name() (r string) {
	r = c.name
	return
}

func (c *connCons) Exec(cmd *AdmCmd) (r string, e error) {
	return
}

// end
