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

type UserGrp interface {
	GetGrp(string) ([]string, error)
}

// QCMng manages quotas and consumptions
type QMng struct {
	// accumulative quotas map
	AccQ *sync.Map
	Grp  UserGrp
}

func (q *QMng) Get(usr string) (n uint64, e error) {
	g, e := q.GetGrp(usr)
	for _, j := range g {
		gq, ok := q.AccQ.Load(j)
		if ok {
			n += gq.(uint64)
		}
	}
	return
}

type StrVal struct {
	Str string `json:"str"`
	Val uint64 `json:"val"`
}

func (q *QMng) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	if r.Method == h.MethodGet {
		mp := make(map[string]uint64)
		q.AccQ.Range(func(k, v interface{}) (ok bool) {
			ks, vu := k.(string), v.(uint64)
			mp[ks], ok = vu, true
			return
		})
		e = Encode(w, &mp)
	} else if r.Method == h.MethodPost {
		// add quota value if name is not in the dictionary
		// replace quota value if name is in the dictionary
		// delete key value pair if value is 0
		sv := new(StrVal)
		e = Decode(r.Body, sv)
		if e == nil {
			if sv.Val == 0 {
				q.AccQ.Delete(sv.Str)
			} else {
				q.AccQ.Store(sv.Str, sv.Val)
			}
		}
	}
	writeErr(w, e)
}

// NoResourceMsg is the message sent when no resource is found
// for processing the request
func NoResourceMsg(r *h.Request, t time.Time,
	usr string) (e error) {
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

func NotFoundKey() (e error) {
	e = fmt.Errorf("Not found key")
	return
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
