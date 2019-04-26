package pmproxy

import (
	"encoding/json"
	"io"
	"sync"
)

// QuotaMap is the object made for storing the quotas
// associated to user groups
type QuotaMap struct {
	mp *sync.Map
}

// NewQMFromR creates a new QuotaMap from a serialized
// JSON map[string]uint64
func NewQMFromR(r io.Reader) (qm *QuotaMap, e error) {
	dec, m := json.NewDecoder(r),
		make(map[string]uint64)
	e = dec.Decode(&m)
	if e == nil {
		qm = &QuotaMap{
			mp: new(sync.Map),
		}
		for k, v := range m {
			qm.mp.Store(k, v)
		}
	}
	return
}

// Load loads a value associated to the supplied key
func (q *QuotaMap) Load(key string) (v uint64, ok bool) {
	var iv interface{}
	iv, ok = q.mp.Load(key)
	if ok {
		v, ok = iv.(uint64)
		if !ok {
			println("Failed type assertion at QuotaMap.Load")
		}
	}
	return
}
