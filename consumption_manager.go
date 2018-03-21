package pmproxy

import (
	h "net/http"
	"sync"
)

type CMng struct {
	Name string
	Cons *sync.Map
}

type StrVal struct {
	Str string
	Val uint64
}

// SrvCs is an h.HandleFunc for serving and modifying
// consumptions
func (c *CMng) SrvCs(w h.ResponseWriter, r *h.Request) {
	var e error
	if r.Method == h.MethodGet {
		mp := make(map[string]uint64)
		c.Cons.Range(func(k, v interface{}) (b bool) {
			mp[k.(string)] = v.(uint64)
			b = true
			return
		})
		e = Encode(w, &mp)
	} else if r.Method == h.MethodPost {
		// load value
		cs := new(StrVal)
		e = Decode(r.Body, cs)
		if e == nil {
			v, ok := c.Cons.Load(cs.Str)
			if ok {
				e = Encode(w, v)
			}
		}
	} else if e == nil && r.Method == h.MethodPut {
		// store or delete value
		cs := new(StrVal)
		e = Decode(r.Body, cs)
		if e == nil {
			if cs.Val == 0 {
				c.Cons.Delete(cs.Str)
			} else {
				c.Cons.Store(cs.Str, cs.Val)
			}
		}
	}
	writeErr(w, e)
}
