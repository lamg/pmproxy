package pmproxy

import (
	"sync"
	"time"
)

type dwnConsR struct {
	name     string
	ipQuotaN string
	ipq      func(string) uint64
	iu       ipUser

	userCons   *sync.Map
	lastReset  time.Time
	resetCycle time.Duration
	mapWriter  func(map[string]uint64)
}

func (d *dwnConsR) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.name = stringE(i, fe)
			},
		},
		{
			ipQuotaK,
			func(i interface{}) {
				d.ipQuotaN = stringE(i, fe)
			},
		},
		{
			lastResetK,
			func(i interface{}) {
				d.lastReset = stringDateE(i, fe)
			},
		},
		{
			resetCycleK,
			func(i interface{}) {
				d.resetCycle = durationE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (d *dwnConsR) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:       d.name,
		ipQuotaK:    d.ipQuotaN,
		lastResetK:  d.lastReset.Format(time.RFC3339),
		resetCycleK: d.resetCycle.String(),
	}
	mp := make(map[string]uint64)
	d.userCons.Range(func(k, v interface{}) (b bool) {
		ks, vu := k.(string), v.(uint64)
		mp[ks] = vu
		return
	})
	d.mapWriter(mp)
	return
}

func (d *dwnConsR) managerKF(c *cmd) (kf []kFunc) {
	return
}

func (d *dwnConsR) consR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			// the reset cycle property is maintained on demand,
			// rather than at regular time lapses
			d.keepResetCycle()

			cons := uint64(0)
			user, ok := d.iu(ip)
			if ok {
				d.userCons.LoadOrStore(user, cons)
			}
			return
		},
		can: func(ip string, down int) (ok bool) {
			user, ok := d.iu(ip)
			if ok {
				cons, b := d.userCons.Load(user)
				limit := d.ipq(ip)
				ok = b && cons.(uint64) <= limit
			}
			return
		},
		update: func(ip string, down int) {
			user, ok := d.iu(ip)
			if ok {
				v, _ := d.userCons.Load(user)
				cons := v.(uint64)
				d.userCons.Store(user, cons+uint64(down))
			}
		},
		close: func(ip string) {},
	}
	return
}

func (d *dwnConsR) keepResetCycle() {
	// this method maintains the property that if the current
	// time is greater or equal to d.lastReset + d.resetCycle,
	// then all consumptions are set to 0
	now := time.Now()
	cy := now.Sub(d.lastReset)
	if cy >= d.resetCycle {
		d.userCons = new(sync.Map)
		d.lastReset = d.lastReset.Add(d.resetCycle)
	}
}
