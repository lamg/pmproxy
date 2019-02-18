package pmproxy

import (
	"fmt"

	"sync"
)

type ipQuotaS struct {
	name        string
	ipg         ipGroup
	quotaCache  *sync.Map
	groupQuotaM *sync.Map
}

type ipQuota func(string) uint64

func (p *ipQuotaS) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				n := p.get(c.RemoteAddr)
				c.bs = []byte(fmt.Sprint(n))
			},
		},
		{
			del,
			func() {
				p.del(c.RemoteAddr)
			},
		},
	}
	return
}

func (p *ipQuotaS) get(ip string) (n uint64) {
	v, ok := p.quotaCache.Load(ip)
	if ok {
		n = v.(uint64)
	} else {
		gs, e := p.ipg(ip)
		if e == nil {
			inf := func(i int) {
				q := p.groupQuota(gs[i])
				n = n + q
			}
			forall(inf, len(gs))
			p.quotaCache.Store(ip, n)
		}
	}
	return
}

func (p *ipQuotaS) del(ip string) {
	p.quotaCache.Delete(ip)
}

func (p *ipQuotaS) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	var m map[string]uint64
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				p.name = stringE(i, fe)
			},
		},
		{
			quotaMapK,
			func(i interface{}) {
				m = stringMapUint64E(i, fe)
			},
		},
		{
			quotaMapK,
			func(i interface{}) {
				p.groupQuotaM = new(sync.Map)
				for k, v := range m {
					p.groupQuotaM.Store(k, v)
				}
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

type groupQuota func(string) uint64

func (p *ipQuotaS) groupQuota(group string) (n uint64) {
	v, ok := p.groupQuotaM.Load(group)
	if ok {
		n = v.(uint64)
	}
	return
}

func (p *ipQuotaS) set(group string, n uint64) {
	p.groupQuotaM.Store(group, n)
}

func (p *ipQuotaS) show() (mp map[string]uint64) {
	mp = make(map[string]uint64)
	p.groupQuotaM.Range(func(k, v interface{}) (ok bool) {
		mp[k.(string)], ok = v.(uint64), true
		return
	})
	return
}

func (p *ipQuotaS) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:   p.name,
		quotasK: p.show(),
	}
	return
}
