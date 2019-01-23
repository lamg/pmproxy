package pmproxy

import (
	rl "github.com/juju/ratelimit"
	"github.com/spf13/cast"
	"time"
)

const (
	KiB         = 1024
	MiB         = 1024 * KiB
	durationK   = "duration"
	capacityK   = "capacity"
	bwConsT     = "bwCons"
	setDuration = "set-duration"
	getDuration = "get-duration"
	setCapacity = "set-capacity"
	getCapacity = "get-capacity"
)

// bandwidth consumption limiter
type bwCons struct {
	Name     string `json:"name"`
	rl       *rl.Bucket
	Duration time.Duration `json:"duration"`
	Capacity int64         `json:"capacity"`
}

func newBwCons(name string, interval time.Duration,
	capacity int64) (bw *bwCons) {
	bw = &bwCons{
		Name:     name,
		rl:       rl.NewBucket(interval, capacity),
		Duration: interval,
		Capacity: capacity,
	}
	return
}

func mpErr(m map[string]interface{},
	fe func(error), fi func(interface{})) (fk func(string)) {
	fk = func(k string) {
		v, ok := m[k]
		if ok {
			fi(v)
		} else {
			fe(NoKey(k))
		}
	}
	return
}

func (b *bwCons) fromMap(i interface{}) (e error) {
	m, e := cast.ToStringMapE(i)
	me := func(fi func(interface{})) (fk func(string)) {
		fk = mpErr(m, func(d error) { e = d }, fi)
		return
	}
	fe := []struct {
		k string
		f func(interface{})
	}{
		{
			nameK,
			func(i interface{}) {
				b.Name, e = cast.ToStringE(i)
			},
		},
		{
			durationK,
			func(i interface{}) {
				b.Duration, e = cast.ToDurationE(i)
			},
		},
		{
			capacityK,
			func(i interface{}) {
				b.Capacity, e = cast.ToInt64E(i)
			},
		},
	}
	if e == nil {
		bLnSrch(func(i int) (b bool) {
			me(fe[i].f)(fe[i].k)
			b = e != nil
			return
		},
			len(fe))
	}
	return
}

func (b *bwCons) init() {
	b.rl = rl.NewBucket(b.Duration, b.Capacity)
}

func (b *bwCons) consR() (c *consR) {
	c = &consR{
		open: func(i ip) (ok bool) {
			ok = true
			return
		},
		can: func(i ip, d download) (ok bool) {
			b.rl.Wait(int64(n))
			ok = true
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
	}
	return
}

func (b *bwCons) admin(a *AdmCmd) (bs []byte, e error) {
	switch a.Cmd {
	case setDuration:
		b.Duration = a.FillInterval
	case getDuration:
		bs = []byte(b.Duration.String())
	case setCapacity:
		b.Capacity = a.Capacity
	case getCapacity:
		bs = []byte(strconv.FormatInt(b.Capacity, 10))
	default:
		e = NoCmd(a.Cmd)
	}
	return
}

func (b *bwCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:     b.Name,
		durationK: b.Duration.String(),
		capacityK: b.Capacity,
	}
	tỹpe = bwConsT
	return
}
