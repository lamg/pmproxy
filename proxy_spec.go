package pmproxy

import (
	h "net/http"
	"time"

	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
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
	Exec(*AdmCmd) error
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
	Iface     string
	Bandwidth *Rate
	Span      *rt.RSpan
	Cr        ConsR
}

// ConsR is an interface for restricting the amount of
// bytes a connection can consume
type ConsR interface {
	Can(int) bool
	UpdateCons(int)
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
	cmd := new(AdmCmd)
	e := Decode(r.Body, cmd)
	if e == nil {
		e = p.adm.Exec(cmd)
	}
	if e != nil {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

// AdmCmd is an administration command
type AdmCmd struct {
}
