package pmproxy

import (
	"io"
	"sync"
)

type MapPrs struct {
	// map of string to uint64
	mp *sync.Map
	wf WriterFct
	dt time.Time
	iv time.Duration
}

func NewMapPrs(wf WriterFct, dt time.Time,
	iv time.Duration) (r *MapPrs) {
	r = &MapPrs{
		mp: new(sync.Map),
		wf: wf,
		dt: dt,
		iv: iv,
	}
	return
}

func (p *MapPrs) Persist() (e error) {
	mp := make(map[string]uint64)
	var bs []byte
	q.rqc.Range(func(k, v interface{}) (b bool) {
		mp[k.(string)], b = v.(uint64), true
		return
	})
	p.wf.NextWriter()
	e = p.wf.Err()
	if e == nil {
		bs, e = json.Marshal(mp)
	}
	if e == nil {
		_, e = q.wf.Current().Write(bs)
	}
	return
}

func (p *MapPrs) Store(key string, val uint64) {
	p.mp.Store(key, val)
	p.SetZero()
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

func (p *MapPrs) SetZero() {

}
