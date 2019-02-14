package pmproxy

import (
	"fmt"
	"github.com/spf13/cast"
	"sync"
)

type ipQuotaS struct {
	name       string
	ipGroup    *ipGroupS
	quotaCache *sync.Map
	groupQuota *sync.Map
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
			nameK,
			func(i interface{}) {
				p.ipGroup = &ipGroup{
					groupCache: new(sync.Map),
					groupQuota: new(sync.Map),
				}
				p.ipGroup.userGroupN = p.name
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
				for k, v := range m {
					p.groupQuota.Store(k, v)
				}
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

type groupQuota func(string) uint64

func (p *ipQuotaS) get(group string) (n uint64) {
	v, ok := p.groupQuota.Load(group)
	if ok {
		n = v.(uint64)
	}
	return
}

func (p *ipQuotaS) set(group string, n uint64) {
	p.groupQuota.Store(group, n)
}

func (p *ipQuotaS) show() (mp map[string]uint64) {
	mp = make(map[string]uint64)
	p.groupQuota.Range(func(k, v interface{}) (ok bool) {
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
