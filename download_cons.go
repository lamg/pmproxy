package pmproxy

import "sync"

// downloaded data consumption limiter
type dwnCons struct {
	name    string
	iu      IPUser
	usrCons *sync.Map
	limit   uint64
}

// ConsR implementation

func (d *dwnCons) Open(ip string) (ok bool) {
	cons := uint64(0)
	user := d.iu.User(ip)
	if user != "" {
		d.usrCons.LoadOrStore(ip, cons)
	}
	ok = true
	return
}

func (d *dwnCons) Can(ip string, n int) (ok bool) {
	user := d.iu.User(ip)
	ok = false
	if user != "" {
		cons, b := d.usrCons.Load(user)
		ok = b && cons.(uint64) <= d.limit
	}
	return
}

func (d *dwnCons) UpdateCons(ip string, n int) {
	user := d.iu.User(ip)
	u, ok := d.usrCons.Load(user)
	if ok {
		cons := u.(uint64)
		d.usrCons.Store(user, cons+uint64(n))
	}
}

func (d *dwnCons) Close(ip string) {

}

// end

// Admin implementation

func (d *dwnCons) Name() (r string) {
	r = d.name
	return
}

func (d *dwnCons) Exec(cmd *AdmCmd) (r string, e error) {

	return
}

// end
// end