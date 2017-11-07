package pmproxy

import (
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/lamg/clock"
)

// initPar groups the initial parameters
type initPar struct {
	RemoteAddr string
	url        *url.URL
	tm         time.Time
}

type rConn struct {
	io.ReadCloser
	cn Cons
	// Throttle coeficient
	tc float32
	// End time of this connection
	end time.Time
	clk clock.Clock
}

func (c *rConn) Read(p []byte) (n int, e error) {
	rp := make([]byte, len(p))
	n, e = c.Read(rp)
	ok := c.cn.Increase(n)
	if ok && c.clk.Now().Before(c.end) {
		copy(p, rp)
	} else {
		c.Close()
		e = fmt.Errorf("No tiene acceso")
	}
	return
}

// Cons interfaces with consumption storage
type Cons interface {
	Increase(int) bool
}
