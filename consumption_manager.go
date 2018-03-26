package pmproxy

import (
	"encoding/json"
	h "net/http"
	"sync"
)

type CMng struct {
	Name string
	Cons *sync.Map
	Sm   *SMng
}

type StrVal struct {
	Str string
	Val uint64
}

func (c *CMng) Get(ip string) (n *uint64, ok bool) {
	usr, ok := c.Sm.MatchUsr(ip)
	if ok {
		v, okl := c.Cons.Load(ip)
		if okl {
			n = &(v.(uint64))
		} else {
			n = &0
			c.Cons.Store(ip, n)
		}
	} else {

	}
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

type cmng struct {
	Name string            `json:"name"`
	Cons map[string]uint64 `json:"cons"`
}

func (c *CMng) MarshalJSON() (bs []byte, e error) {
	x := &cmng{
		Name: c.Name,
		Cons: make(map[string]uint64),
	}
	c.Cons.Range(func(k, v interface{}) (b bool) {
		key, value, b := k.(string), v.(uint64), true
		x.Cons[key] = value
		return
	})
	bs, e = json.Marshal(x)
	return
}

func (c *CMng) UnmarshalJSON(bs []byte) (e error) {
	x := new(cmng)
	e = json.Unmarshal(bs, x)
	if e == nil {
		c.Name, c.Cons = x.Name, new(sync.Map)
		for k, v := range x.Cons {
			c.Cons.Store(k, v)
		}
	}
	return
}
