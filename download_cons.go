package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/clock"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

// downloaded data consumption limiter
type dwnCons struct {
	cl         clock.Clock
	Name       string        `json:"name"`
	IPUser     string        `json:"ipUser"`
	IPQuota    string        `json: "groupQuota"`
	LastReset  time.Time     `json:"lastReset"`
	ResetCycle time.Duration `json:"resetCycle"`

	iu      func(string) ipUser
	gq      func(string) ipQuota
	usrCons *sync.Map
}

func (d *dwnCons) consR() (c *consR) {
	c = &consR{
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
	}
	return
}

const (
	dwnConsT = "dwnCons"
)

func (d *dwnCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:      d.Name,
		ipUserK:    d.IPUser,
		userQtK:    d.usrQtS.Name,
		lastResetK: d.LastReset.String(),
		resetCycle: d.ResetCycle.String(),
	}
	tỹpe = dwnCons
	mp := make(map[string]uint64)
	d.usrCons.Range(func(k, v interface{}) (b bool) {
		ks, vu := k.(string), v.(uint64)
		mp[ks] = vu
		return
	})
	bs, _ := json.Marshal(mp)
	fl := d.filename()
	ioutil.WriteFile(fl, bs, os.ModePerm)
	// TODO log errors
	return
}

func (d *dwnCons) admin(c *AdmCmd) (bs []byte, e error) {
	kf := []kfunc{
		{
			show,
			func() {
				v, ok := d.usrCons.Load(cmd.User)
				if ok {
					bs = []byte(fmt.Sprintf("%d", v))
				} else {
					e = NoEntry(cmd.User)
				}
			},
		},
		{
			reset,
			func() {
				if cmd.IsAdmin {
					_, ok := d.usrCons.Load(cmd.User)
					if ok {
						d.usrCons.Store(cmd.User, uint64(0))
					} else {
						e = NoEntry(cmd.User)
					}
				}
			},
		},
	}
	exF(kf, cmd.Cmd, func(d error) { e = d })
	return
}

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

func (d *dwnCons) fromMap(i interface{}) (e error) {
	fs := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.Name, e = cast.ToStringE(i)
			},
		},
		{
			ipUserK,
			func(i interface{}) {
				d.IPUser, e = cast.ToStringE(i)
			},
		},
		{
			ipQuotaK,
			func(i interface{}) {
				d.IPQuota, e = cast.ToStringE(i)
			},
		},
		{
			lastResetK,
			func(i interface{}) {
				d.LastReset, e = cast.StringToDate(i)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				d.ResetCycle, e = stringToDuration(s)
			},
		},
	}
	mapKF(
		fs,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	var bs []byte
	var mp map[string]uint64
	fe := []func(){
		func() {}, // this evaluates e != nil before continuing
		// with the execution of posterior procedures in this
		// slice
		func() {
			fl := d.filename()
			bs, e = ioutil.ReadFile(fl)
		},
		func() {
			mp = make(map[string]uint64)
			e = json.Unmarshal(bs, &mp)
		},
		func() {
			for k, v := range mp {
				d.usrCons.Store(k, v)
			}
		},
	}
	bLnSrch(
		ferror(fe, func() bool { return e != nil }),
		len(fe),
	)
	return
}

func (d *dwnCons) filename() (f string) {
	fl := viper.ConfigFileUsed()
	dir := path.Dir(fl)
	f = path.Join(dir, d.Name+".json")
	return
}

func stringToDuration(i interface{}) (d time.Duration,
	e error) {
	s, e := cast.ToStringE(i)
	if e == nil {
		d, e = time.ParseDuration(s)
	}
	return
}
