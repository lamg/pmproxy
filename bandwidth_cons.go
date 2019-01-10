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
	NameF    string `json:"name"`
	rl       *rl.Bucket
	Duration time.Duration `json:"duration"`
	Capacity int64         `json:"capacity"`
}

func newBwCons(name string, interval time.Duration,
	capacity int64) (bw *bwCons) {
	bw = &bwCons{
		NameF:    name,
		rl:       rl.NewBucket(interval, capacity),
		Duration: interval,
		Capacity: capacity,
	}
	return
}

func (b *bwCons) init() {
	b.rl = rl.NewBucket(b.Duration, b.Capacity)
}

// ConsR implementation

func (b *bwCons) Open(ip string) (ok bool) {
	ok = true
	return
}

func (b *bwCons) Can(ip string, n int) (ok bool) {
	b.rl.Wait(int64(n))
	ok = true
	return
}

func (b *bwCons) UpdateCons(ip string, n int) {
	return
}

func (b *bwCons) Close(ip string) {
}

func (b *bwCons) Name() (r string) {
	r = b.NameF
	return
}

// end

// Admin implementation

func (b *bwCons) Exec(cmd *AdmCmd) (r string, e error) {
	// the user must delete this manager,
	// instead of trying to change it
	return
}
