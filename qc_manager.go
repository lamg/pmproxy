package pmproxy

import (
	"fmt"
	h "net/http"
	"sync"
	"time"

	"github.com/lamg/clock"

	rt "github.com/lamg/rtimespan"
)

// QCMng manages quotas and consumptions
type QCMng struct {
	// resource-*Quota
	Quota *sync.Map
	// resource-*Cons
	Cons *sync.Map
	// determines resources
	QDet ResDet
	CDet ResDet
	//
	Cl clock.Clock
	// current user
	cUsr string
	qr   QtCsRec
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
func (q *QCMng) MaybeResp(w h.ResponseWriter, r *h.Request) (y bool) {
	nw := q.Cl.Now()
	resq := q.QDet.Det(r, nw, q.cUsr)
	v, ok := q.Quota.Load(resq)
	var u interface{}
	if ok {
		resc := q.CDet.Det(r, nw, q.cUsr)
		u, ok = q.Cons.Load(resc)
	}
	if ok {
		cs, qt := u.(*Cons), v.(*Quota)
		q.qr.Rec(&QtCs{Qt: qt, Cs: cs})
	}
	if !ok {
		w.Write([]byte(NoResourceMsg(r, nw, q.cUsr)))
	}
	y = !ok
	return
}

// NoResourceMsg is the message sent when no resource is found
// for processing the request
func NoResourceMsg(r *h.Request, t time.Time, usr string) (s string) {
	s = fmt.Sprintf("No resource found for %s in %s at %s", usr,
		r.RemoteAddr, t.Format(time.RFC3339))
	return
}

// QtCs quota cons pair
type QtCs struct {
	Qt *Quota
	Cs *Cons
}

// Quota represents the parameters and resources
// available for determined connection
type Quota struct {
	// Maximum amount of bytes available for downloading
	Dwn uint64
	// Network interface the connection must be made over
	Iface string
	// Time span for consuming/using this resource
	Span *rt.RSpan
	// Connection's throttling specification
	Thr float64
	// Maximum amount of connections per host
	MCn byte
}

// Cons represents the consumed quota, if can be
type Cons struct {
	// Amount of downloaded bytes
	Dwn uint64
	// Amount of used connections
	Cns byte
}
