package pmproxy

import "sync"

// downloaded data consumption limiter
type dwnCons struct {
	iu      IPUser
	usrCons *sync.Map
	limit   uint64
}

func (d *dwnCons) Can(ip string, n int) (ok bool) {
	cons := uint64(0)
	u, b := d.usrCons.LoadOrStore(ip, cons)
	if b {
		cons = u.(uint64)
	}
	ok = cons <= d.limit
	return
}

func (d *dwnCons) UpdateCons(ip string, n int) {
	u, _ := d.usrCons.Load(ip)
	cons := u.(uint64)
	d.usrCons.Store(ip, cons+uint64(n))
}

func (d *dwnCons) Close() {

}
