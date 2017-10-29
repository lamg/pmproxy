package pmproxy

// TODO substitute calls to time.Now for a call
// to an environment independent procedure

import (
	"context"
	"fmt"
	"net"
	h "net/http"
	"time"

	g "github.com/lamg/goproxy"
)

// PMProxy is the proxy server
type PMProxy struct {
	px      *g.ProxyHttpServer
	wIntURL string
	rmng    *RRConnMng
}

// NewPMProxy creates a new PMProxy
func NewPMProxy(r *RRConnMng, wi string) (p *PMProxy) {
	p = &PMProxy{g.NewProxyHttpServer(), wi, r}

	p.px.OnResponse().DoFunc(p.procResp)
	p.px.ConnectDial = p.newConCountHTTPS
	p.px.Tr.DialContext = p.newConCountHTTP
	p.px.NonproxyHandler = h.HandlerFunc(localHandler)
	return
}

func localHandler(w h.ResponseWriter, r *h.Request) {
	w.WriteHeader(h.StatusNotFound)
}

func (p *PMProxy) newConCountHTTP(c context.Context, nt,
	ad string) (n net.Conn, e error) {
	v := c.Value(RemoteAddr("RemoteAddress"))
	if v != nil {
		x, ok := v.(*h.Request)
		if ok {
			n, e = p.rmng.newConn(nt, ad, x, time.Now())
		}
	}
	return
}

func (p *PMProxy) newConCountHTTPS(nt, ad string,
	c *g.ProxyCtx) (n net.Conn, e error) {
	n, e = p.rmng.newConn(nt, ad, c.Req, time.Now())
	return
}

func (p *PMProxy) procResp(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
	x = p.rmng.ProcResponse(r)
	return
}

// RemoteAddr is the type to be used as key
// of RemoteAddr value in context
type RemoteAddr string

const rmAddr = "RemoteAddress"

func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	if p.rmng.CanDo(r, time.Now()) {
		h.Redirect(w, r,
			fmt.Sprintf("%s/?url=%s", p.wIntURL,
				r.URL.String()),
			h.StatusTemporaryRedirect)
		// { redirected to the proxy's web interface
		//	 with the requested URL as parameter }
	} else {
		q := r.WithContext(context.WithValue(context.Background(),
			RemoteAddr(rmAddr), r))
		p.px.ServeHTTP(w, q)
		// { served with request's remote address in
		//   in context's values }
	}
}
