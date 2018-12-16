package pmproxy

import (
	"io"
	"net"
	h "net/http"
	"time"
)

type conf struct {
}

func admin(c *conf) (hf h.HandlerFunc) {
	return
}

type cntr func(time.Time, *h.Request) (net.Conn, error)

func connect(c *conf) (n cntr) {
	return
}

func store(c *conf) {

}

func load(rd io.Reader) (c *conf) {
	return
}
