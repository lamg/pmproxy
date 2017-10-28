package pmproxy

import (
	"context"
	"fmt"
	"net"
	h "net/http"
	"strings"
	"time"

	"github.com/lamg/errors"
	g "github.com/lamg/goproxy"
)

// PMProxy is the proxy server
type PMProxy struct {
	qa        *QAdm
	px        *g.ProxyHttpServer
	rl        *RLog
	loginAddr string
	uf        map[string]string
}

// NewPMProxy creates a new PMProxy
func NewPMProxy(qa *QAdm, rl *RLog, loginAddr string,
	uf map[string]string) (p *PMProxy) {
	p = &PMProxy{qa, g.NewProxyHttpServer(), rl, loginAddr, uf}
	p.px.OnRequest(g.ReqConditionFunc(p.cannotRequest)).
		DoFunc(p.forbiddenAcc)

	p.px.OnResponse().DoFunc(p.logResp)
	p.px.ConnectDial = p.newConCountHTTPS
	p.px.Tr.DialContext = p.newConCountHTTP
	p.px.NonproxyHandler = h.HandlerFunc(localHandler)
	return
}

func localHandler(w h.ResponseWriter, r *h.Request) {
	w.WriteHeader(h.StatusNotFound)
}

func (p *PMProxy) forbiddenAcc(r *h.Request,
	c *g.ProxyCtx) (q *h.Request, t *h.Response) {
	q, t = r, g.NewResponse(r, "text/plain",
		h.StatusForbidden, "No tiene acceso")
	return
}

func (p *PMProxy) newConCountHTTP(c context.Context, nt,
	ad string) (n net.Conn, e error) {
	v := c.Value(RemoteAddr("RemoteAddress"))
	if v != nil {
		x, ok := v.(string)
		if ok {
			n, e = p.newConCount(nt, ad, x)
		}
	}
	return
}

func (p *PMProxy) newConCountHTTPS(nt, ad string,
	c *g.ProxyCtx) (n net.Conn, e error) {
	n, e = p.newConCount(nt, ad, c.Req.RemoteAddr)
	return
}

func (p *PMProxy) newConCount(ntw, addr,
	rAddr string) (r net.Conn, e error) {
	n, er := p.getUsrNtIf(rAddr)
	e = errors.UnwrapErr(er)
	var ief *net.Interface
	if e == nil {
		ief, e = net.InterfaceByName(n)
	}
	var laddr []net.Addr
	if e == nil {
		laddr, e = ief.Addrs()
	}
	var la *net.IPNet
	if e == nil {
		ok, i := false, 0
		for !ok && i != len(laddr) {
			la = laddr[i].(*net.IPNet)
			ok = la.IP.To4() != nil
			if !ok {
				i = i + 1
			}
		}
		if i == len(addr) {
			e = fmt.Errorf("Not found IPv4 address")
		}
	}
	var cn net.Conn
	if e == nil {
		tca := &net.TCPAddr{IP: la.IP}
		d := &net.Dialer{LocalAddr: tca}
		cn, e = d.Dial(ntw, addr)
	}
	if e == nil {
		r = &conCount{cn, p.qa, addr, rAddr}
	}
	return
}

func (p *PMProxy) getUsrNtIf(r string) (n string,
	e *errors.Error) {
	h, _, ec := net.SplitHostPort(r)
	e = errors.NewForwardErr(ec)
	var v interface{}
	if e == nil {
		var ok bool
		v, ok = p.qa.sm.sessions.Load(h)
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorKey,
				Err: fmt.Errorf("Not found key %s in p.qa.sm.sessions",
					h),
			}
		}
	}
	var u *User
	if e == nil {
		var ok bool
		u, ok = v.(*User)
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorTypeAssertion,
				Err:  fmt.Errorf("v is not an *User"),
			}
		}
	}
	if e == nil {
		var ok bool
		n, ok = p.uf[u.QuotaGroup]
		if !ok {
			e = &errors.Error{
				Code: errors.ErrorKey,
				Err:  fmt.Errorf("Not found key %s", u.QuotaGroup),
			}
		}
	}
	return
}

type conCount struct {
	net.Conn
	qa    *QAdm
	addr  string
	rAddr string
}

func (c *conCount) Read(p []byte) (n int, e error) {
	k, ip := getK(c.qa, c.addr, c.rAddr)
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

type usrDt struct {
	cf   float32
	req  *h.Request
	time time.Time
}

func (p *PMProxy) logResp(r *h.Response,
	c *g.ProxyCtx) (x *h.Response) {
	var log *Log
	if r != nil {
		tm := time.Now()
		log = &Log{
			// User is set by p.rl.Log
			Addr:      r.Request.RemoteAddr,
			Meth:      r.Request.Method,
			URI:       r.Request.URL.String(),
			Proto:     r.Request.Proto,
			Time:      tm,
			Elapsed:   5 * time.Millisecond, //FIXME not the meaning of E.
			From:      "-",
			Action:    "TCP_MISS",
			Hierarchy: "DIRECT",
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "-"
		} else {
			ct = strings.Split(ct, ";")[0]
			// MIME type parameters droped
		}
		log.ContentType = ct
		k, ip := getK(p.qa, r.Request.Host, r.Request.RemoteAddr)
		if k > 0 {
			cs := float32(r.Request.ContentLength) * k
			p.qa.addCons(ip, uint64(cs))
		}
		p.rl.record(log)
	}
	x = r
	return
}

func getK(qa *QAdm, host, raddr string) (k float32, ip string) {
	hs, pr, _ := net.SplitHostPort(host)
	ip, _, _ = net.SplitHostPort(raddr)
	k = qa.canReq(ip, hs, pr, time.Now())
	return
}

func (p *PMProxy) cannotRequest(q *h.Request,
	c *g.ProxyCtx) (r bool) {
	k, _ := getK(p.qa, q.Host, q.RemoteAddr)
	c.UserData = &usrDt{
		cf:  k,
		req: q,
	}
	r = k < 0
	return
}

// RemoteAddr is the type to be used as key
// of RemoteAddr value in context
type RemoteAddr string

const rmAddr = "RemoteAddress"

func (p *PMProxy) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	ra, _, _ := net.SplitHostPort(r.RemoteAddr)
	if p.qa.nlf(ra) {
		h.Redirect(w, r,
			fmt.Sprintf("%s/?url=%s", p.loginAddr,
				r.URL.String()),
			h.StatusTemporaryRedirect)
		// { redirected to the proxy's web interface
		//	 with the requested URL as parameter }
	} else {
		q := r.WithContext(context.WithValue(context.Background(),
			RemoteAddr(rmAddr),
			r.RemoteAddr))
		p.px.ServeHTTP(w, q)
		// { served with request's remote address in
		//   in context's values }
	}
}

// Dialer is an interface to custom dialers that
// can be used in place of net.Dial
type Dialer interface {
	Dial(string, string) (net.Conn, error)
}

// NetDialer is a Dialer that uses net.Dial
type NetDialer struct {
}

// Dial dials using net.Dial
func (n *NetDialer) Dial(ntw,
	addr string) (c net.Conn, e error) {
	c, e = net.Dial(ntw, addr)
	return
}
