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

type QuotaDet struct {
	Quota uint64
	QtM   *QMng
	Usr   *StringDet
}

func (c *QuotaDet) Det(r *h.Request, d time.Time) (ok bool,
	e error) {
	ok, e = c.Usr.Det(r, d)
	if ok && e == nil {
		c.Quota, e = c.QtM.Get(c.Usr.Str)
	}
	return
}

func (c *QuotaDet) MarshalJSON() (bs []byte, e error) {
	mp := make(map[string]uint64)
	c.QtM.AccQ.Range(func(k, v interface{}) (c bool) {
		ks, vu := k.(string), v.(uint64)
		mp[ks] = vu
		return
	})
	bs, e = json.Marshal(&mp)
	return
}

func (c *QuotaDet) UnmarshalJSON(bs []byte) (e error) {
	mp := make(map[string]uint64)
	e = json.Unmarshal(bs, &mp)
	if e == nil {
		c.QtM = &QMng{
			AccQ: new(sync.Map),
		}
		for k, v := range mp {
			c.QtM.AccQ.Store(k, v)
		}
	}
	return
}
