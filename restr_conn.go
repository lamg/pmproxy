package pmproxy

import (
	"fmt"
	"net"
	"time"
)

type conCount struct {
	net.Conn
	qa    *QAdm
	addr  string
	rAddr string
}

func (c *conCount) Read(p []byte) (n int, e error) {
	k, ip := c.getK()
	if k >= 0 {
		n, e = c.Conn.Read(p)
		// { n ≥ 0 }
		cs := k * float32(n)
		c.qa.addCons(ip, uint64(cs))
	} else {
		e = fmt.Errorf("No tiene acceso")
	}
	return
}

func (c *conCount) getK() (k float32, ip string) {
	hs, pr, _ := net.SplitHostPort(c.addr)
	ip, _, _ = net.SplitHostPort(c.rAddr)
	k, _ = c.qa.canReq(ip, hs, pr, time.Now())
	return
}
