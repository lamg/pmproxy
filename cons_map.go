package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
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
	closed bool
	bf     *bytes.Buffer
	pr     *Persister
}

// NewConsMap creates a new ConsMap
func NewConsMap(lr time.Time, rt time.Duration,
	uc map[string]uint64, pr *Persister) (c *ConsMap) {
	c = &ConsMap{lr: lr,
		rt:     rt,
		closed: true,
		bf:     bytes.NewBufferString(""),
		mp:     new(sync.Map),
		pr:     pr,
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
func NewCMFromR(r io.Reader,
	pr *Persister) (c *ConsMap, e *errors.Error) {
	d, om := json.NewDecoder(r), new(OMap)
	ec := d.Decode(om)
	if ec == nil {
		c = NewConsMap(om.LastReset, om.ResetT, om.UserCons, pr)
	}
	e = errors.NewForwardErr(ec)
	return
}

// Load loads a value associated to a key in the dictionary
func (p *ConsMap) Load(key string) (v uint64, ok bool) {
	var iv interface{}
	iv, ok = p.mp.Load(key)
	if ok {
		v, ok = iv.(uint64)
		if !ok {
			println("Failed type assertion at ConsMap.Load")
		}
	}
	return
}

// Store stores a key-value pair in the dictionary
func (p *ConsMap) Store(key string, val uint64) {
	n := newTime(p.lr, p.rt)
	if n != p.lr {
		p.Reset()
		p.lr = n
	}
	p.mp.Store(key, val)
	p.bf.Reset()
	enc := json.NewEncoder(p.bf)
	om := &OMap{
		LastReset: p.lr,
		ResetT:    p.rt,
		UserCons:  make(map[string]uint64),
	}
	p.mp.Range(func(k, v interface{}) (b bool) {
		sk, oks := k.(string)
		uv, oku := v.(uint64)
		if !oks {
			fmt.Printf("Assertion of %v as string failed\n", k)
		}
		if !oku {
			fmt.Printf("Assertion of %v as uint64 failed\n", v)
		}
		b = oks && oku
		if b {
			om.UserCons[sk] = uv
		}
		return
	})
	e := enc.Encode(om)
	if e == nil {
		p.pr.Persist(p.bf)
	}
}

// Reset sets all values to 0
func (p *ConsMap) Reset() {
	p.mp.Range(func(a, b interface{}) (x bool) {
		p.mp.Store(a, uint64(0))
		x = true
		return
	})
}
