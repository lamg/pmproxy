package pmproxy

import (
	"sync"
)

type groupQuotaS struct {
	mäp *sync.Map
}

type groupQuota func(string) uint64

func (p *groupQuotaS) get(group string) (n uint64) {
	v, ok := p.mäp.Load(group)
	if ok {
		n = v.(uint64)
	}
	return
}

func (p *groupQuotaS) set(group string, n uint64) {
	p.mäp.Store(group, n)
}

func (p *groupQuotaS) show() (i interface{}) {
	mp := make(map[string]uint64)
	p.mäp.Range(func(k, v interface{}) (ok bool) {
		mp[k.(string)], ok = v.(uint64), true
		return
	})
	i = mp
	return
}
