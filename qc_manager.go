package pmproxy

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"net/url"
	"sync"
	"time"

	"github.com/lamg/clock"

	rt "github.com/lamg/rtimespan"
)

// QCMng manages quotas and consumptions
type QCMng struct {
	// resource-*Quota
	Rm *RdMng
	// resource-*Cons
	Cons *sync.Map
	// determines resources
	Det ResDet
	//
	Cl clock.Clock
	// current user
	cUsr string
	qr   QtCsRec
	okQt bool
}

// QtCsRec is a receiver of *QtCs
type QtCsRec interface {
	Rec(qc *QtCs)
}

// Rec is the UsrRec implementation
func (q *QCMng) Rec(usr string) {
	q.cUsr = usr
}

// MaybeResp handles requests to the proxy. If any
// has no resource associated, then it will respond
// with an error page
func (q *QCMng) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	nw := q.Cl.Now()
	res, e := q.Det.Det(r, nw, q.cUsr)
	var cs *Cons
	if e == nil {
		v, ok := q.Cons.Load(res.InD.Det(r, nw, q.cUsr))
		if ok {
			cs = v.(*Cons)
		} else {
			e = NoResourceMsg(r, nw, q.cUsr)
		}
	}
	if e == nil {
		q.qr.Rec(&QtCs{Qt: res.Qt, Cs: cs})
	} else {
		w.Write([]byte(e.Error()))
	}
	q.okQt = e != nil
	return
}

func (q *QCMng) V() (y bool) {
	y = q.okQt
	return
}

// NoResourceMsg is the message sent when no resource is found
// for processing the request
func NoResourceMsg(r *h.Request, t time.Time, usr string) (e error) {
	e = fmt.Errorf("No resource found for %s in %s at %s", usr,
		r.RemoteAddr, t.Format(time.RFC3339))
	return
}

// QtCs quota cons pair
type QtCs struct {
	Qt *Quota
	Cs *Cons
}

// TODO following handlers expose resource managing interface.
// Implement JSON marshal and unmarshal in types to be modified
// by those handlers

// SrvQt is an h.HandleFunc for serving and modifying quotas
func (q *QCMng) SrvRes(w h.ResponseWriter, r *h.Request) {
	var e error
	if r.Method == h.MethodGet {

	} else if r.Method == h.MethodPost {

	} else if r.Method == h.MethodPut {

	} else if r.Method == h.MethodDelete {

	} else {
		e = NotSuppMeth(r.Method)
	}
	writeErr(w, e)
}

// SrvCs is an h.HandleFunc for serving and modifying
// consumptions
func (q *QCMng) SrvCs(w h.ResponseWriter, r *h.Request) {
	var e error
	if r.Method == h.MethodGet {

	} else if r.Method == h.MethodPost {

	} else if r.Method == h.MethodPut {

	} else if r.Method == h.MethodDelete {

	} else {
		e = NotSuppMeth(r.Method)
	}
	writeErr(w, e)
}

// Quota represents the parameters and resources
// available for determined connection
type Quota struct {
	// Maximum amount of bytes available for downloading
	Dwn uint64 `json:"dwn"`
	// Network interface the connection must be made over
	Iface string `json:"iface"`
	// Time span for consuming/using this resource
	Span *rt.RSpan `json:"span"`
	// Connection's throttling specification
	Thr float64 `json:"thr"`
	// Maximum amount of connections per host
	MCn byte `json:"mCn"`
	// Maybe a proxy for handling requests
	Proxy string `json:"proxy"`
	proxy *url.URL
}

func (q *Quota) UnmarshalJSON(data []byte) (e error) {
	e = json.Unmarshal(data, q)
	if e == nil {
		q.proxy, e = url.Parse(q.Proxy)
	}
	return
}

// Cons represents the consumed quota, if can be
type Cons struct {
	// Amount of downloaded bytes
	Dwn uint64 `json:"dwn"`
	// Amount of used connections
	Cns byte `json:"cns"`
}
