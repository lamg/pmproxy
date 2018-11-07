package pmproxy

import (
	"net"
	h "net/http"
	"time"

	"github.com/lamg/clock"
)

// ProxyCtl has the handlers for the HTTP servers
type ProxyCtl struct {
	clock clock.Clock
	rp    RSpec
	proxy ProxySpec
	adm   Admin
}

// Admin is the resource specificator administrator
type Admin interface {
	Exec(*AdmCmd) (string, error)
}

// Transport underlying transport for github.com/lamg/proxy
type Transport interface {
	h.RoundTripper
	DialContext(context.Context, string, string) (net.Conn, error)
}

// RSpec specifies which resources correspond to a request
// at the supplied time
type RSpec interface {
	Spec(time.Time, *h.Request) (*Spec, error)
}

// Spec is a resource specification
type Spec struct {
	Iface    string
	ProxyURL string
	Cr       []ConsR
}

// ConsR is an interface for restricting several aspects of a
// connection
type ConsR interface {
	Open(string) bool
	Can(string, int) bool
	UpdateCons(string, int)
	Close(string)
}

// Proxy is the handler to be used by the HTTP proxy server
func (p *ProxyCtl) Proxy(w h.ResponseWriter, r *h.Request) {
	t := p.clock.Now()
	s, e := p.rp.Spec(t, r)
	if e == nil {
		p.proxy.ServeSpec(s, w, r)
	} else {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

// Admin is the handler that implements the administration
// interface to be served by an HTTP server
func (p *ProxyCtl) Admin(w h.ResponseWriter, r *h.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	var cmd *AdmCmd
	if e == nil {
		cmd = new(AdmCmd)
		e = Decode(r.Body, cmd)
	}
	var res string
	if e == nil {
		r.Body.Close()
		cmd.Args = append(cmd.Args, ip)
		res, e = p.adm.Exec(cmd)
	}
	if e == nil {
		_, e = w.Write([]byte(res))
	}
	if e != nil {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

// AdmCmd is an administration command
type AdmCmd struct {
	Manager string   `json:"mng"`
	Cmd     string   `json:"cmd"`
	Args    []string `json:"args"`
	Pos     []int    `json:"pos"`
	Rule    *Rule    `json:"rule"`
}
