package pmproxy

import (
	"encoding/json"
	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"io"
	"sync"
	"time"
)

const (
	// ErrorNewMapPrs is the error returned by NewMapPrs
	ErrorNewMapPrs = iota
	// ErrorMarshalMP is the error returned when trying to
	// marshal a map[string]uint64 as JSON
	ErrorMarshalMP
	// ErrorWritePersist is the error when calling Write in
	// persist method
	ErrorWritePersist
)

// MapPrs is a map of string to uint64 that can be concurrently
// accessed. Also it persist its values to an io.Writer given
// by a WriterFct when an interval of iv duration ends, starting
// counting the interval at dt.
type MapPrs struct {
	// map of string to uint64
	mp *sync.Map
	wf w.WriterFct
	dt time.Time
	iv time.Duration
}

// NewMapPrs is a constructor for MapPrs.
// rc: has a JSON object serialized that can be parsed
// as map[string]uint64
// wf: gives the io.Writers for persisting the map
// dt: time to start persisting
// iv: interval between persists
func NewMapPrs(rc io.Reader, wf w.WriterFct, dt time.Time,
	iv time.Duration) (r *MapPrs, e *errors.Error) {
	mp, dc, om := new(sync.Map), json.NewDecoder(rc),
		make(map[string]uint64)
	ec := dc.Decode(&om)
	if ec == nil {
		for k, v := range om {
			mp.Store(k, v)
		}
	} else {
		e = &errors.Error{
			Code: ErrorNewMapPrs,
			Err:  ec,
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

func (p *MapPrs) persist() (e *errors.Error) {
	mp := make(map[string]uint64)
	p.mp.Range(func(k, v interface{}) (b bool) {
		mp[k.(string)], b = v.(uint64), true
		return
	})
	p.wf.NextWriter()
	e = p.wf.Err()
	var bs []byte
	if e == nil {
		var ec error
		bs, ec = json.Marshal(mp)
		if ec != nil {
			e = &errors.Error{
				Code: ErrorMarshalMP,
				Err:  ec,
			}
		}
	}
	if e == nil {
		var ec error
		_, ec = p.wf.Current().Write(bs)
		if ec != nil {
			e = &errors.Error{
				Code: ErrorWritePersist,
				Err:  e,
			}
		}
	}
	return
}

func (p *MapPrs) store(key string, val uint64) {
	p.mp.Store(key, val)
	p.persistIfTime()
}

func (p *MapPrs) load(key string) (val uint64, ok bool) {
	var v interface{}
	v, ok = p.mp.Load(key)
	if ok {
		val, ok = v.(uint64)
	}
	return
}

func (p *MapPrs) rangeF(f func(k string, v uint64) bool) {
	p.mp.Range(func(a, b interface{}) (x bool) {
		x = f(a.(string), b.(uint64))
		return
	})
}

func (p *MapPrs) persistIfTime() (b bool, e *errors.Error) {
	var n time.Time
	n = newTime(p.dt, p.iv)
	b = n != p.dt
	if b {
		p.dt, e = n, p.persist()
	}
	return
}

func (p *MapPrs) reset() {
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
