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
	Name       string        `json:"name"`
	IPUser     string        `json:"ipUser"`
	GroupQuota string        `json: "groupQuota"`
	LastReset  time.Time     `json:"lastReset"`
	ResetCycle time.Duration `json:"resetCycle"`

	iu      func(string) ipUser
	gq      func(string) ipQuota
	usrCons *sync.Map
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

func (d *dwnCons) manager() (m *manager) {
	m = &manager{
		name: d.Name,
		cons: &consR{
			open: func(i ip) (ok bool) {
				// the reset cycle property is maintained on demand,
				// rather than at regular time lapses
				d.keepResetCycle()

				cons := uint64(0)
				user := d.iu.User(ip)
				if user != "" {
					d.usrCons.LoadOrStore(user, cons)
				}
				ok = true
				return
			},
			can: func(i ip, d download) (ok bool) {
				user := d.iu.User(ip)
				ok = false
				if user != "" {
					cons, b := d.usrCons.Load(user)
					limit := d.grp(i)
					ok = b && cons.(uint64) <= limit
				}
				return
			},
			update: func(i ip, d download) {
				user := d.iu.User(ip)
				u, ok := d.usrCons.Load(user)
				if ok {
					cons := u.(uint64)
					d.usrCons.Store(user, cons+uint64(n))
				}
			},
			close: func(i ip) {},
		},
		mtch: idMatch,
		adm: func(c *AdmCmd) (bs []byte, e error) {
			switch c.Cmd {
			case "show-cons":
				v, ok := d.usrCons.Load(cmd.User)
				if ok {
					r = fmt.Sprintf("%d", v)
				} else {
					e = NoEntry(cmd.User)
				}
			case "reset-cons":
				if cmd.IsAdmin {
					_, ok := d.usrCons.Load(cmd.User)
					if ok {
						d.usrCons.Store(cmd.User, uint64(0))
					} else {
						e = NoEntry(cmd.User)
					}
				}
			case "show-quota-user":
				r, e = d.qtAdm(true, false, false, false, cmd.User,
					"", 0)
			case "set-quota-group":
				r, e = d.qtAdm(false, false, true, false, "",
					cmd.Group, cmd.Limit)
				d.UserQt = d.qtSer()
			case "del-group":
				r, e = d.qtAdm(false, false, false, true, "",
					cmd.Group, 0)
				d.UserQt = d.qtSer()
			default:
				e = NoCmd(c.Cmd)
			}
			return
		},
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK:      d.Name,
				ipUserK:    d.IPUser,
				userQtK:    d.usrQtS.Name,
				lastResetK: d.LastReset.String(),
				resetCycle: d.ResetCycle.String(),
			}
			return
		},
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
