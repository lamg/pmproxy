package pmproxy

import (
	"encoding/json"
	h "net/http"
	"sync"
)

type CMng struct {
	Name string
	Cons *sync.Map
}

func NewCMng(name string) (c *CMng) {
	c = &CMng{
		Name: name,
		Cons: new(sync.Map),
	}
	return
}

type StrVal struct {
	Str string
	Val uint64
}

type ConsAdd struct {
	cons *sync.Map
	user string
	m    uint64
	cf   float32
}

func (d *ConsAdd) CanGet(n, quota uint64,
	cf float32) (b bool) {
	v, ok := d.cons.Load(d.user)
	var m uint64
	if ok {
		d.m, d.cf = v.(uint64), cf
		m = d.m + uint64(float32(n)*cf)
	}
	b = m < quota
	return
}

// Add depends on a previous call to CanGet
func (d *ConsAdd) Add(n uint64) {
	m := d.m + uint64(float32(n)*d.cf)
	d.cons.Store(d.user, m)
	return
}

func (c *CMng) Adder(user string) (d *ConsAdd) {
	d = &ConsAdd{
		cons: c.Cons,
		user: user,
	}
	return
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
