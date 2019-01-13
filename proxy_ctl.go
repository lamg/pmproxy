package pmproxy

import (
	"io"
	"net"
	h "net/http"
	"time"
)

// ProxyCtl has the handlers for the HTTP servers
type ProxyCtl struct {
	// contains the fields for initializing
	// github.com/lamg/proxy.Proxy
	PrxFls *SpecCtx
	adm    *config
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

// AdmCmd is an administration command
type AdmCmd struct {
	Manager      string        `json:"mng"`
	Cmd          string        `json:"cmd"`
	User         string        `json:"user"`
	Pass         string        `json:"pass"`
	Pos          []int         `json:"pos"`
	Rule         *rule         `json:"rule"`
	Secret       string        `json:"secr"`
	RemoteIP     string        `json:"remoteIP"`
	MngName      string        `json:"mngName"`
	MngType      string        `json:"mngType"`
	Capacity     int64         `json:"capacity"`
	FillInterval time.Duration `json:"fillInterval"`
	IPUser       string        `json:"ipUser"`
	Limit        uint64        `json:"limit"`
	AD           *adConf       `json:"ad"`
	DialTimeout  time.Duration `json:"dialTimeout"`
	Group        string        `json:"group"`
	IsAdmin      bool          `json:"isAdmin"`
}
