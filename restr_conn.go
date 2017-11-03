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
	rp := make([]byte, len(p))
	n, e = c.Conn.Read(rp)
	if c.qa.cons(c.rAddr, c.addr, time.Now(), n) {
		copy(p, rp)
	} else {
		e = fmt.Errorf("No tiene acceso")
	}
	return
}
