package pmproxy

import (
	rl "github.com/juju/ratelimit"
	"time"
)

const (
	KiB = 1024
	MiB = 1024 * KiB
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

func (b *bwCons) init() {
	b.rl = rl.NewBucket(b.Duration, b.Capacity)
}

func (b *bwCons) manager() (m *manager) {
	c := &consR{
		open: func(i ip) (ok bool) {
			ok = true
			return
		},
		can: func(i ip, d download) (ok bool) {
			b.rl.Wait(int64(n))
			ok = true
			return
		},
		update: func(i ip, d download) {

		},
		close: func(i ip) {

		},
	}
	m = &manager{
		name:    b.Name,
		tỹpe:    "bwCons",
		consR:   c,
		matcher: idMatch,
		adm: func(a *AdmCmd) (bs []byte, e error) {
			switch a.Cmd {
			case "set-duration":
				b.Duration = a.FillInterval
			case "get-duration":
				bs = []byte(b.Duration.String())
			case "set-capacity":
				b.Capacity = a.Capacity
			case "get-capacity":
				bs = []byte(strconv.FormatInt(b.Capacity, 10))
			default:
				e = NoCmd(a.Cmd)
			}
			return
		},
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK:     b.Name,
				durationK: b.Duration.String(),
				capacityK: b.Capacity,
			}
			return
		},
	}
	return
}
