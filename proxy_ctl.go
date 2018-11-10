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
	// contains the fields for initializing
	// github.com/lamg/proxy.Proxy
	prxFls *SpecCtx
	adm    Admin
}

// Admin is the resource specificator administrator
type Admin interface {
	Exec(*AdmCmd) (string, error)
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

// ConsR stands for consumption restrictor, it restricts several
// aspects of a connection
type ConsR interface {
	Open(string) bool
	Can(string, int) bool
	UpdateCons(string, int)
	Close(string)
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
		cmd.RemoteIP = ip
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
	Manager  string `json:"mng"`
	Cmd      string `json:"cmd"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Pos      []int  `json:"pos"`
	Rule     *Rule  `json:"rule"`
	Secret   string `json:"secr"`
	RemoteIP string `json:"remoteIP"`
	MngName  string `json:"mngName"`
	MngType  string `json:"mngType"`
}
