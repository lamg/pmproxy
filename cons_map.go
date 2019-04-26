package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lamg/clock"
	"io"
	"sync"
	"time"
)

// ConsMap maintains a dictionary of user to consumption
// that is reseted when time.Now() >= lr + rt
type ConsMap struct {
	lr     time.Time
	rt     time.Duration
	mp     *sync.Map
	c      clock.Clock
	closed bool
}

// NewConsMap creates a new ConsMap
func NewConsMap(lr time.Time, rt time.Duration,
	uc map[string]uint64, cl clock.Clock) (c *ConsMap) {
	c = &ConsMap{lr: lr,
		rt:     rt,
		closed: true,
		mp:     new(sync.Map),
		c:      cl,
	}
	for k, v := range uc {
		c.mp.Store(k, v)
	}
	return
}

// OMap is the struct that can be serialized as JSON
// containing all the information to create a new ConsMap
type OMap struct {
	ResetT    time.Duration     `json:"resetTime"`
	LastReset time.Time         `json:"lastReset"`
	UserCons  map[string]uint64 `json:"userCons"`
}

// NewCMFromR creates a new ConsMap reading a OMap serialized
// as JSON in r
func NewCMFromR(r io.Reader, cl clock.Clock) (c *ConsMap, e error) {
	d, om := json.NewDecoder(r), new(OMap)
	e = d.Decode(om)
	if e == nil {
		if om.ResetT == 0 {
			e = fmt.Errorf("resetTime field must not be 0")
		} else {
			c = NewConsMap(om.LastReset, om.ResetT, om.UserCons, cl)
		}
	}
	return
}

// Load loads a value associated to a key in the dictionary
func (p *ConsMap) Load(key string) (v uint64, ok bool) {
	n := newTime(p.lr, p.rt, p.c)
	if n != p.lr {
		p.Reset()
		p.lr = n
	}
	// Reset if it's time to do so, triggered not
	// at the reset time, but when a value is requested
	// (lazy reset).iv, ok := p.mp.Load(key)
	iv, ok := p.mp.Load(key)
	if ok {
		v, ok = iv.(uint64)
	}
	return
}

// clock.Now() - d > i ≡ n ≠ d
// n ≠ d ⇒ n - d < i
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

// Store stores a key-value pair in the dictionary
func (p *ConsMap) Store(key string, val uint64) {
	p.mp.Store(key, val)
}

func (p *ConsMap) Persist() (rd io.Reader) {
	om := &OMap{
		LastReset: p.lr,
		ResetT:    p.rt,
		UserCons:  make(map[string]uint64),
	}
	p.mp.Range(func(k, v interface{}) (b bool) {
		sk := k.(string)
		uv := v.(uint64)
		om.UserCons[sk] = uv
		b = true
		return
	})
	bf := bytes.NewBufferString("")
	Encode(bf, om)
	rd = bf
	return
}

// Reset sets all values to 0
func (p *ConsMap) Reset() {
	p.mp = new(sync.Map)
}
