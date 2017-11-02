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
	if c.qa.cons(c.rAddr, c.addr, time.Now(), len(p)) {
		n, e = c.Conn.Read(p)
	} else {
		e = fmt.Errorf("No tiene acceso")
	}
	return
}
