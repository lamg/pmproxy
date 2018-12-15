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
	NameF      string `json:"name" toml:"name"`
	IPUser     string `json:"ipUser" toml:"ipUser"`
	iu         IPUser
	usrCons    *sync.Map
	UserQt     usrQt
	LastReset  time.Time     `json:"lastReset" toml:"lastReset"`
	ResetCycle time.Duration `json:"resetCycle" toml:"resetCycle"`
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
		limit := d.UserQt(user)
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
	if cmd.Cmd == "show" {
		v, ok := d.usrCons.Load(cmd.User)
		if ok {
			r = fmt.Sprintf("%d", v)
		} else {
			NoEntry(cmd.User)
		}
	} else if cmd.Cmd == "reset" {
		_, ok := d.usrCons.Load(cmd.User)
		if ok {
			d.usrCons.Store(cmd.User, uint64(0))
		} else {
			e = NoEntry(cmd.User)
		}
	} else if cmd.Cmd == "reset-all" {
		// race condition with ConsR implementation?
		d.usrCons = new(sync.Map)
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
