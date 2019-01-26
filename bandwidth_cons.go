package pmproxy

import (
	"fmt"
	rl "github.com/juju/ratelimit"
	"strconv"
	"time"
)

const (
	KiB       = 1024
	MiB       = 1024 * KiB
	durationK = "duration"
	capacityK = "capacity"
	bwConsT   = "bwCons"
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

func (b *bwCons) fromMapKF(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				b.Name = stringE(i, fe)
			},
		},
		{
			durationK,
			func(i interface{}) {
				b.Duration = stringDurationE(i, fe)
			},
		},
		{
			capacityK,
			func(i interface{}) {
				b.Capacity = int64E(i, fe)
			},
		},
	}
	return
}

func (b *bwCons) init() {
	b.rl = rl.NewBucket(b.Duration, b.Capacity)
}

func (b *bwCons) consR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			ok = true
			return
		},
		can: func(ip string, down int) (ok bool) {
			b.rl.Wait(int64(b.Duration))
			ok = true
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}

func (b *bwCons) admin(a *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	cs = []cmdProp{
		{
			cmd:  set,
			prop: durationK,
			f:    func() { b.Duration = a.FillInterval },
		},
		{
			cmd:  set,
			prop: capacityK,
			f:    func() { b.Capacity = a.Capacity },
		},
		{
			cmd:  get,
			prop: durationK,
			f:    func() { fb([]byte(b.Duration.String())) },
		},
		{
			cmd:  get,
			prop: capacityK,
			f: func() {
				fb([]byte(strconv.FormatInt(b.Capacity, 10)))
			},
		},
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

func NoProp(p string) (e error) {
	e = fmt.Errorf("No property %s", p)
	return
}
