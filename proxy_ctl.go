package pmproxy

import (
	"io"
	"net"
	h "net/http"
)

// ProxyCtl has the handlers for the HTTP servers
type ProxyCtl struct {
	// contains the fields for initializing
	// github.com/lamg/proxy.Proxy
	PrxFls  *SpecCtx
	adm     *globAdm
	Persist func(io.Writer) error
}

func NewProxyCtl() (p *ProxyCtl, e error) {
	return
}

// ServeHTTP is the handler that implements the
// administration interface to be served by an HTTP server
func (p *ProxyCtl) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	ips, _, e := net.SplitHostPort(r.RemoteAddr)
	var cmd *AdmCmd
	if e == nil {
		cmd = new(AdmCmd)
		e = Decode(r.Body, cmd)
	}
	var bs []byte
	if e == nil {
		r.Body.Close()
		cmd.RemoteIP = ips
		bs, e = p.adm.exec(cmd)
	}
	if e == nil {
		_, e = w.Write(bs)
	}
	if e != nil {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

func (p *ProxyCtl) Persist(w io.Writer) (e error) {
	e = p.adm.persist(w)
	return
}
