package pmproxy

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/lamg/clock"
)

// CMng manages user consumption
type CMng struct {
	Name       string
	Cons       *sync.Map
	ResetCycle time.Duration
	LastReset  time.Time
	Cl         clock.Clock
}

type yCMng struct {
	Name       string
	Cons       map[string]uint64
	ResetCycle time.Duration
	LastReset  time.Time
}

// MarshalYAML is the yaml.Marshaler implementation
func (c *CMng) MarshalYAML() (v interface{}, e error) {
	yc := yCMng{
		Name:       c.Name,
		Cons:       make(map[string]uint64),
		ResetCycle: c.ResetCycle,
		LastReset:  c.LastReset,
	}
	c.Cons.Range(func(key, value interface{}) (ok bool) {
		yc.Cons[key.(string)] = value.(uint64)
		ok = true
		return
	})
	v = yc
	return
}

// UnmarshalYAML is the yaml.Unmarshaler implementation
func (c *CMng) UnmarshalYAML(umf func(interface{}) error) (e error) {
	yc := new(yCMng)
	e = umf(yc)
	if e == nil {
		c.Name = yc.Name
		c.LastReset = yc.LastReset
		c.ResetCycle = yc.ResetCycle
		c.Cl = new(clock.OSClock)
		if c.Cons == nil {
			c.Cons = new(sync.Map)
		}
		for k, v := range yc.Cons {
			c.Cons.Store(k, v)
		}
	}
	return
}

// NewCMng returns a new instance of CMng
func NewCMng(name string) (c *CMng) {
	c = &CMng{
		Name: name,
		Cons: new(sync.Map),
	}
	return
}

// ConsAdd registers user consumption and says if the user
// is allowed to do so
type ConsAdd struct {
	cons *CMng
	user string
	cf   float32
}

// CanGet returns whether n bytes are allowed to be consumed by
// the user
func (d *ConsAdd) CanGet(n, quota uint64,
	cf float32) (b bool) {
	v, ok := d.cons.Cons.Load(d.user)
	var m uint64
	if ok {
		m, d.cf = v.(uint64), cf
		m = m + uint64(float32(n)*cf)
	}
	b = m < quota
	return
}

// Add depends on a previous call to CanGet
func (d *ConsAdd) Add(n uint64) {
	m := d.cons.Load(d.user)
	m = m + uint64(float32(n)*d.cf)
	d.cons.Store(d.user, m)
	return
}

// Adder returns a consumption adder for the supplied user
func (c *CMng) Adder(user string) (d *ConsAdd) {
	d = &ConsAdd{
		cons: c,
		user: user,
		cf:   1,
	}
	return
}

// Load loads the user consumption
func (c *CMng) Load(user string) (m uint64) {
	c.checkResetTime()
	v, ok := c.Cons.Load(user)
	m = uint64(0)
	if ok {
		m = v.(uint64)
	}
	return
}

// Store consumption associated to user
func (c *CMng) Store(user string, m uint64) {
	c.Cons.Store(user, m)
}

func (c *CMng) checkResetTime() {
	nt := newTime(c.LastReset, c.ResetCycle, c.Cl)
	if !nt.Equal(c.LastReset) {
		c.LastReset = nt
		c.Cons = new(sync.Map)
	}
}

const (
	userPath = "/{user}"
)

// PrefixHandler returns the h.Handler for interacting with CMng
func (c *CMng) PrefixHandler() (p *PrefixHandler) {
	p = &PrefixHandler{
		Prefix: "consumption_manager",
	}
	rt, path := mux.NewRouter(), "/"+c.Name
	rt.HandleFunc(path, c.ServeCons).Methods(h.MethodGet)
	rt.HandleFunc(path+userPath, c.ServeUserCons).Methods(h.MethodGet)
	rt.HandleFunc(path+userPath, c.ServeModUsrCons).Methods(h.MethodPut)
	p.Hnd = rt
	return
}

// ServeCons is an h.HandlerFunc
func (c *CMng) ServeCons(w h.ResponseWriter, r *h.Request) {
	// r.Method = h.MethodGet
	mp := make(map[string]uint64)
	c.Cons.Range(func(k, v interface{}) (b bool) {
		mp[k.(string)] = v.(uint64)
		b = true
		return
	})
	e := Encode(w, &mp)
	writeErr(w, e)
}

const (
	// UserVar is the URL variable for getting the user name
	UserVar = "user"
)

// ServeUserCons is an h.HandlerFunc for showing user consumption
func (c *CMng) ServeUserCons(w h.ResponseWriter, r *h.Request) {
	// r.Method = h.MethodGet
	vrs := mux.Vars(r)
	usr := vrs[UserVar]
	// got user name from url
	v, ok := c.Cons.Load(usr)
	if ok {
		_, e := fmt.Fprintf(w, "%d", v)
		writeErr(w, e)
	}
}

// ServeModUsrCons is an h.HandlerFunc for modifying user
// consumption
func (c *CMng) ServeModUsrCons(w h.ResponseWriter, r *h.Request) {
	// r.Method == h.MethodPut
	vrs, v := mux.Vars(r), uint64(0)
	usr := vrs[UserVar]
	// got user name from url
	_, e := fmt.Fscanf(r.Body, "%d", &v)
	if e == nil {
		if v == 0 {
			c.Cons.Delete(usr)
		} else {
			c.Cons.Store(usr, v)
		}
	}
	writeErr(w, e)
}

type cmng struct {
	Name string            `json:"name"`
	Cons map[string]uint64 `json:"cons"`
}

// MarshalJSON is the json.Marshaler implementation
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

// UnmarshalJSON is the json.Unmarshaler implementation
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

// clock.Now() - d > i  ≡  n ≠ d
// n ≠ d  ⇒  n - d < i
func newTime(d time.Time, i time.Duration,
	c clock.Clock) (n time.Time) {
	var nw time.Time
	var ta time.Duration
	nw = c.Now()
	// { nw - d < 290 years (by time.Duration's doc.)}
	var ci time.Duration
	ci = nw.Sub(d)
	// { cintv: interval between now and the last}
	ta = ci / i
	n = d.Add(i * ta)
	return
}
