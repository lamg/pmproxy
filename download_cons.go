package pmproxy

import (
	"fmt"
	"github.com/lamg/clock"
	"sync"
	"time"
)

// downloaded data consumption limiter
type dwnCons struct {
	cl         clock.Clock
	Name       string `json:"name"`
	IPUser     string `json:"ipUser"`
	iu         IPUser
	usrCons    *sync.Map
	usrQt      usrQt
	qtAdm      qtAdm
	qtSer      usrQtSer
	UserQt     *usrQtS       `json:"userQt"`
	LastReset  time.Time     `json:"lastReset"`
	ResetCycle time.Duration `json:"resetCycle"`
}

type srchIU func(string) (IPUser, error)
type srchUG func(string) (usrGrp, error)

func initDwn(d *dwnCons, si srchIU, su srchUG) (e error) {
	d.iu, e = si(d.IPUser)
	var ug usrGrp
	if e == nil {
		d.usrCons = new(sync.Map)
		ug, e = su(d.UserQt.UsrGrp)
	}
	if e == nil {
		d.usrQt, d.qtAdm, d.qtSer = newUsrQt(d.UserQt.Name,
			d.UserQt.Quotas, ug)
		d.usrCons = new(sync.Map)
		d.iu, e = si(d.IPUser)
	}
	return
}

// ConsR implementation

func (d *dwnCons) Open(ip string) (ok bool) {
	// the reset cycle property is maintained on demand, rather than
	// at regular time lapses
	d.keepResetCycle()

	cons := uint64(0)
	user := d.iu.User(ip)
	if user != "" {
		d.usrCons.LoadOrStore(user, cons)
	}
	ok = true
	return
}

func (d *dwnCons) Can(ip string, n int) (ok bool) {
	user := d.iu.User(ip)
	ok = false
	if user != "" {
		cons, b := d.usrCons.Load(user)
		limit := d.usrQt(user)
		ok = b && cons.(uint64) <= limit
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

func (d *dwnCons) Name() (r string) {
	r = d.NameF
	return
}

// end

// Admin implementation

func (d *dwnCons) Exec(cmd *AdmCmd) (r string, e error) {
	if cmd.Cmd == "show-cons" {
		v, ok := d.usrCons.Load(cmd.User)
		if ok {
			r = fmt.Sprintf("%d", v)
		} else {
			e = NoEntry(cmd.User)
		}
	} else if cmd.IsAdmin && cmd.Cmd == "reset-cons" {
		if cmd.IsAdmin {
			_, ok := d.usrCons.Load(cmd.User)
			if ok {
				d.usrCons.Store(cmd.User, uint64(0))
			} else {
				e = NoEntry(cmd.User)
			}
		}
	} else if cmd.IsAdmin && cmd.Cmd == "reset-all" {
		// race condition with ConsR implementation?
		d.usrCons = new(sync.Map)
	} else if cmd.IsAdmin && cmd.Cmd == "show-quota-user" {
		r, e = d.qtAdm(true, false, false, false, cmd.User, "", 0)
	} else if cmd.Cmd == "show-quota-group" {
		r, e = d.qtAdm(false, true, false, false, "", cmd.Group, 0)
	} else if cmd.IsAdmin && cmd.Cmd == "set-quota-group" {
		r, e = d.qtAdm(false, false, true, false, "", cmd.Group,
			cmd.Limit)
		d.UserQt = d.qtSer()
	} else if cmd.IsAdmin && cmd.Cmd == "del-group" {
		r, e = d.qtAdm(false, false, false, true, "", cmd.Group, 0)
		d.UserQt = d.qtSer()
	} else {
		e = NoCmd(cmd.Cmd)
	}
	return
}

// end

func (d *dwnCons) keepResetCycle() {
	// this method maintains the property that if the current
	// time is greater or equal to d.LastReset + d.ResetCycle,
	// then all consumptions are set to 0
	now := d.cl.Now()
	cy := now.Sub(d.LastReset)
	if cy >= d.ResetCycle {
		d.usrCons = new(sync.Map)
		d.LastReset = d.LastReset.Add(d.ResetCycle)
	}
}
