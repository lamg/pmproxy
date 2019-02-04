package pmproxy

import (
	"sync"
)

type ipQuotaS struct {
	ipGroup    ipGroup
	quotaCache *sync.Map
	groupQuota groupQuota
}

type ipQuota func(string) uint64

func (p *ipQuotaS) get(ip string) (n uint64) {
	v, ok := p.quotaCache.Load(ip)
	if ok {
		n = v.(uint64)
	} else {
		gs, e := p.ipGroup(ip)
		if e == nil {
			inf := func(i int) {
				q := p.groupQuota(gs[i])
				n = n + q
			}
			forall(inf, len(gs))
			p.quotaCache.Store(ip, n)
		}
	}
}

func (p *ipQuotaS) del(ip string) {
	p.quotaCache.Delete(ip)
}
