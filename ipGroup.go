package pmproxy

import (
	"sync"
)

type ipGroupS struct {
	ipUser     ipUser
	groupCache *sync.Map
	userGroupN string
	userGroup  func(string) (userGroup, bool)
}

type ipGroup func(string) ([]string, error)

func (p *ipGroupS) get(ip string) (gs []string, e error) {
	v, ok := p.groupCache.Load(ip)
	if ok {
		gs = v.([]string)
	} else {
		user, ok := p.ipUser(ip)
		if ok {
			grp, ok := p.usrGroup(p.userGroupN)
			if ok {
				gs, e = grp(usr)
			} else {
				e = noKey(p.userGroupN)
			}
		} else {
			e = noKey(ip)
		}
	}
	return
}

func (p *ipGroupS) del(ip string) {
	p.groupCache.Delete(ip)
}
