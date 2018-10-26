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

// ProxySpec is a proxy server that process the request
// according parameters in Spec instance
type ProxySpec interface {
	ServeSpec(*Spec, h.ResponseWriter, *h.Request)
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

type Rate struct {
}

// ConsR is an interface for restricting the amount of
// bytes a connection can consume
type ConsR interface {
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
}
