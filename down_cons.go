package pmproxy

import "sync"

// downloaded data amount consumption limiter for a connection
type dwnCons struct {
	usrDwn *sync.Map
	iu     IPUser
	limit  uint64
}

func (t *dwnCons) Can(ip string, n int) (ok bool) {
	nu := uint64(n)
	user := t.iu.User(ip)
	c, _ := t.usrDwn.Load(user)
	ok = c.(uint64)+nu <= t.limit
	return
}

func (t *dwnCons) UpdateCons(ip string, n int) {

}

func (t *dwnCons) Close(ip string) {

}
