package pmproxy

import (
	"encoding/json"
	. "github.com/lamg/wfact"
	"io"
	"sync"
	"time"
)

type MapPrs struct {
	// map of string to uint64
	mp *sync.Map
	wf WriterFct
	dt time.Time
	iv time.Duration
}

func NewMapPrs(rc io.Reader, wf WriterFct, dt time.Time,
	iv time.Duration) (r *MapPrs, e error) {
	mp, dc, om := new(sync.Map), json.NewDecoder(rc),
		make(map[string]uint64)
	e = dc.Decode(&om)
	if e == nil {
		for k, v := range om {
			mp.Store(k, v)
		}
	}
	r = &MapPrs{
		mp: mp,
		wf: wf,
		dt: dt,
		iv: iv,
	}
	return
}

func (p *MapPrs) Persist() (e error) {
	mp := make(map[string]uint64)
	var bs []byte
	p.mp.Range(func(k, v interface{}) (b bool) {
		mp[k.(string)], b = v.(uint64), true
		return
	})
	p.wf.NextWriter()
	e = p.wf.Err()
	if e == nil {
		bs, e = json.Marshal(mp)
	}
	if e == nil {
		_, e = p.wf.Current().Write(bs)
	}
	return
}

func (p *MapPrs) Store(key string, val uint64) {
	p.mp.Store(key, val)
	p.PersistIfTime()
}

func (p *MapPrs) Load(key string) (val uint64, ok bool) {
	var v interface{}
	v, ok = p.mp.Load(key)
	if ok {
		val, ok = v.(uint64)
	}
	return
}

func (p *MapPrs) Range(f func(k string, v uint64) bool) {
	p.mp.Range(func(a, b interface{}) (x bool) {
		x = f(a.(string), b.(uint64))
		return
	})
}

func (p *MapPrs) PersistIfTime() (b bool, e error) {
	var n time.Time
	n = newTime(p.dt, p.iv)
	b = n != p.dt
	if b {
		p.dt, e = n, p.Persist()
	}
	return
}

func (p *MapPrs) Reset() {
	p.mp.Range(func(a, b interface{}) (x bool) {
		p.mp.Store(a, uint64(0))
		x = true
		return
	})
}

// time.Now() - d > i ≡ n ≠ d
// n ≠ d ⇒ n - d < i
func newTime(d time.Time, i time.Duration) (n time.Time) {
	var nw time.Time
	var ta time.Duration
	nw = time.Now()
	// { nw - d < 290 years (by time.Duration's doc.)}
	var ci time.Duration
	ci = nw.Sub(d)
	// { cintv: interval between now and the last}
	ta = ci / i
	n = d.Add(i * ta)
	return
}
