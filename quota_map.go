package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"io"
	"sync"
)

// QuotaMap is the object made for storing the quotas
// associated to user groups
type QuotaMap struct {
	mp     *sync.Map
	closed bool
	bf     *bytes.Buffer
	pr     *Persister
}

// NewQMFromR creates a new QuotaMap from a serialized
// JSON map[string]uint64
func NewQMFromR(r io.Reader,
	p *Persister) (qm *QuotaMap, e *errors.Error) {
	dec, m := json.NewDecoder(r),
		make(map[string]uint64)
	ec := dec.Decode(&m)
	if e == nil {
		qm = &QuotaMap{
			mp:     new(sync.Map),
			closed: true,
			bf:     bytes.NewBufferString(""),
			pr:     p,
		}
		for k, v := range m {
			qm.mp.Store(k, v)
		}
	}
	e = errors.NewForwardErr(ec)
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

// Store stores a key value pair in the dictionary
func (q *QuotaMap) Store(key string, val uint64) {
	q.mp.Store(key, val)
	q.bf.Reset()
	enc := json.NewEncoder(q.bf)
	m := make(map[string]uint64)
	q.mp.Range(func(k, v interface{}) (ok bool) {
		sk, oks := k.(string)
		uv, oku := v.(uint64)
		if !oks {
			fmt.Printf("Assertion of %v as string failed\n", k)
		}
		if !oku {
			fmt.Printf("Assertion of %v as uint64 failed\n", v)
		}
		ok = oks && oku
		if ok {
			m[sk] = uv
		}
		return
	})
	e := enc.Encode(m)
	if e == nil {
		q.pr.Persist(q.bf)
	}
}
