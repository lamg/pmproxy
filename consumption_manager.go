package pmproxy

import (
	"sync"
)

type CMng struct {
	Cons *sync.Map
}

// SrvCs is an h.HandleFunc for serving and modifying
// consumptions
func (c *CMng) SrvCs(w h.ResponseWriter, r *h.Request) {
	if r.Method == h.MethodPost {
		// load value
		cs := new(StrVal)
		e = Decode(r.Body, cs)
		if e == nil {
			v, ok := q.Cons.Load(cs.Str)
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
				q.Cons.Delete(cs.Str)
			} else {
				q.Cons.Store(k, cs)
			}
		}
	}
	writeErr(w, e)
}
