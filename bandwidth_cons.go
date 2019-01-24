package pmproxy

import (
	"fmt"
	rl "github.com/juju/ratelimit"
	"github.com/spf13/cast"
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

func (b *bwCons) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
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
	mapKF(
		kf,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
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
			b.rl.Wait(int64(b.Duration))
			ok = true
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
	}
	return
}

func (b *bwCons) admin(a *AdmCmd) (bs []byte, e error) {
	cs := []struct {
		cmd  string
		prop string
		f    func()
	}{
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
			f:    func() { bs = []byte(b.Duration.String()) },
		},
		{
			cmd:  get,
			prop: capacityK,
			f: func() {
				bs = []byte(strconv.FormatInt(b.Capacity, 10))
			},
		},
	}
	cmdf, propf := false, false
	bLnSrch(
		func(i int) (b bool) {
			cmdf, propf = cs[i].cmd == a.Cmd, cs[i].prop == a.Prop
			b = cmdf && propf
			if b {
				cs[i].f()
			}
		},
		len(cs),
	)
	if !cmdf {
		e = NoCmd(a.Cmd)
	}
	if !propf {
		e = NoProp(a.Prop)
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
