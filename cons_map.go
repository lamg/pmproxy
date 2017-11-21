package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lamg/errors"
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
		if om.ResetT == 0 {
			e = &errors.Error{
				Code: errors.FormatErr,
				Err:  fmt.Errorf("resetTime field must not be 0"),
			}
		} else {
			c = NewConsMap(om.LastReset, om.ResetT, om.UserCons, pr)
		}
	} else {
		e = errors.NewForwardErr(ec)
	}
	return
}

// Load loads a value associated to a key in the dictionary
func (p *ConsMap) Load(key string) (v uint64, ok bool) {
	n := newTime(p.lr, p.rt, p.pr.c)
	if n != p.lr {
		p.Reset()
		p.lr = n
	}
	// Reset if it's time to do so, triggered not
	// at the reset time, but when a value is requested
	// (lazy reset).
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
	n := newTime(p.lr, p.rt, p.pr.c)
	if n != p.lr {
		p.Reset()
		p.lr = n
	}
	p.mp.Store(key, val)
	p.fillBuffer()
	p.pr.Persist(p.bf)
}

func (p *ConsMap) fillBuffer() {
	p.bf.Reset()
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
	Encode(p.bf, om)
}

// Reset sets all values to 0
func (p *ConsMap) Reset() {
	p.mp.Range(func(a, b interface{}) (x bool) {
		p.mp.Store(a, uint64(0))
		x = true
		return
	})
}
