package pmproxy

import (
	"sync"
)

type ipUserS struct {
	mäp *sync.Map
}

type ipUser func(string) (string, bool)

func (p *ipUserS) get(ip string) (user string, ok bool) {
	v, ok := p.mäp.Load(ip)
	if ok {
		user = v.(string)
	}
	return
}

func (p *ipUserS) del(ip string) {
	p.mäp.Delete(ip)
	return
}

func (p *ipUserS) set(ip, user string) {
	p.mäp.Store(ip, user)
}
