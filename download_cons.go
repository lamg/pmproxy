package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/clock"
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
		open: func(ip string) (ok bool) {
			// the reset cycle property is maintained on demand,
			// rather than at regular time lapses
			d.keepResetCycle()

			cons := uint64(0)
			user := d.iu(d.IPUser)(ip)
			if user != "" {
				d.usrCons.LoadOrStore(user, cons)
			}
			ok = true
			return
		},
		can: func(ip string, down int) (ok bool) {
			user := d.iu(d.IPUser)(ip)
			ok = false
			if user != "" {
				cons, b := d.usrCons.Load(user)
				limit := d.gq(d.IPQuota)(ip)
				ok = b && cons.(uint64) <= limit
			}
			return
		},
		update: func(ip string, down int) {
			user := d.iu(d.IPUser)(ip)
			u, ok := d.usrCons.Load(user)
			if ok {
				cons := u.(uint64)
				d.usrCons.Store(user, cons+uint64(down))
			}
		},
		close: func(ip string) {},
	}
	return
}

const (
	dwnConsT = "dwnCons"
)

func (d *dwnCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:       d.Name,
		ipUserK:     d.IPUser,
		ipQuotaK:    d.IPQuota,
		lastResetK:  d.LastReset.String(),
		resetCycleK: d.ResetCycle.String(),
	}
	tỹpe = dwnConsT
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

func (d *dwnCons) admin(c *AdmCmd, fb fbs,
	fe ferr) (kf []kFunc) {
	kf = []kFunc{
		{
			show,
			func() {
				v, ok := d.usrCons.Load(c.User)
				if ok {
					fb([]byte(fmt.Sprintf("%d", v)))
				} else {
					fe(NoEntry(c.User))
				}
			},
		},
		{
			reset,
			func() {
				if c.IsAdmin {
					_, ok := d.usrCons.Load(c.User)
					if ok {
						d.usrCons.Store(c.User, uint64(0))
					} else {
						fe(NoEntry(c.User))
					}
				}
			},
		},
	}
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

func (d *dwnCons) fromMapKF(fe ferr) (kf []kFuncI) {
	var bs []byte
	var mp map[string]uint64
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.Name = stringE(i, fe)
			},
		},
		{
			ipUserK,
			func(i interface{}) {
				d.IPUser = stringE(i, fe)
			},
		},
		{
			ipQuotaK,
			func(i interface{}) {
				d.IPQuota = stringE(i, fe)
			},
		},
		{
			lastResetK,
			func(i interface{}) {
				d.LastReset = stringDateE(i, fe)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				d.ResetCycle = stringDurationE(i, fe)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				fl := d.filename()
				var e error
				bs, e = ioutil.ReadFile(fl)
				fe(e)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				mp = make(map[string]uint64)
				fe(json.Unmarshal(bs, &mp))
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				for k, v := range mp {
					d.usrCons.Store(k, v)
				}
			},
		},
	}
	return
}

func (d *dwnCons) filename() (f string) {
	fl := viper.ConfigFileUsed()
	dir := path.Dir(fl)
	f = path.Join(dir, d.Name+".json")
	return
}
