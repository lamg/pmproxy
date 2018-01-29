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
	Cl   clock.Clock
	// current user
	cUsr string
	// Quota-Consumption receiver
	Qr   QtCsRec
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

// ServeHTTP handles requests to the proxy. If any
// has no resource associated, then it will respond
// with an error page
func (q *QCMng) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	nw := q.Cl.Now()
	res, e := q.Rm.Det(r, nw, q.cUsr)
	cs := new(Cons)
	if e == nil {
		println("ok")
		println(res == nil)
		println(res.Cn.Net[0])
		ind := res.InD.Det(r, nw, q.cUsr)
		v, ok := q.Cons.Load(ind)
		if ok {
			cs = v.(*Cons)
		} else {
			q.Cons.Store(ind, cs)
		}
	}
	if e == nil {
		q.Qr.Rec(&QtCs{Qt: res.Qt, Cs: cs})
	} else {
		// The message should be written to the user interface
		// rather than the response
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

const (
	index = "index"
)

func getIndex(r *h.Request, l int) (i int, e error) {
	_, e = fmt.Sscanf(r.URL.Query().Get(index), "%d", &i)
	if e != nil || !(0 <= i && i < l) {
		e = IndexOutOfRange()
	}
	return
}

// SrvQt is an h.HandleFunc for serving and modifying quotas
func (q *QCMng) SrvRes(w h.ResponseWriter, r *h.Request) {
	ind, e := getIndex(r, len(q.Rm.rs))
	if e == nil && r.Method == h.MethodGet {
		e = Encode(w, q.Rm.rs[ind])
	} else if r.Method == h.MethodPost {
		// add quota rule
		rs := new(Res)
		e = Decode(r.Body, rs)
		if e == nil {
			q.Rm.rs = append(q.Rm.rs, rs)
		}
	} else if e == nil && r.Method == h.MethodPut {
		// replace quota rule
		rs := new(Res)
		e = Decode(r.Body, rs)
		q.Rm.rs[ind] = rs
	} else if e == nil && r.Method == h.MethodDelete {
		// delete quota rule
		q.Rm.rs[ind], q.Rm.rs[0] = q.Rm.rs[0], q.Rm.rs[ind]
		q.Rm.rs = q.Rm.rs[1:]
	}
	writeErr(w, e)
}

const (
	key = "key"
)

func NotFoundKey() (e error) {
	e = fmt.Errorf("Not found key")
	return
}

func getKey(r *h.Request) (k string, e error) {
	k = r.URL.Query().Get(key)
	if k == "" {
		e = NotFoundKey()
	}
	return
}

// SrvCs is an h.HandleFunc for serving and modifying
// consumptions
func (q *QCMng) SrvCs(w h.ResponseWriter, r *h.Request) {
	k, e := getKey(r)
	if e == nil && r.Method == h.MethodGet {
		v, ok := q.Cons.Load(k)
		if ok {
			e = Encode(w, v)
		}
	} else if e == nil && r.Method == h.MethodPut {
		cs := new(Cons)
		e = Decode(r.Body, cs)
		if e == nil {
			q.Cons.Store(k, cs)
		}
	} else if e == nil && r.Method == h.MethodDelete {
		q.Cons.Delete(k)
	}
	writeErr(w, e)
}

// Quota represents the parameters and resources
// available for determined connection
type Quota struct {
	QuotaJ
	proxy *url.URL
}

type QuotaJ struct {
	// Maximum amount of bytes available for downloading
	Dwn uint64 `json:"dwn"`
	// Network interface the connection must be made over
	Iface string `json:"iface"`
	// Time span for consuming/using this resource
	Span *rt.RSpan `json:"span"`
	// Connection's throttling specification
	Thr float64 `json:"thr"`
	// Maximum amount of connections per host
	MCn uint32 `json:"mCn"`
	// Maybe a proxy for handling requests
	Proxy string `json:"proxy"`
}

func (q *Quota) UnmarshalJSON(data []byte) (e error) {
	qj := QuotaJ{}
	e = json.Unmarshal(data, &qj)
	if e == nil {
		q.proxy, e = url.Parse(q.Proxy)
	}
	if e == nil {
		q.QuotaJ = qj
	}
	return
}

// Cons represents the consumed quota, if can be
type Cons struct {
	// Amount of downloaded bytes
	Dwn uint64 `json:"dwn"`
	// Amount of used connections
	Cns uint32 `json:"cns"`
}
