package pmproxy

import (
	"github.com/juju/ratelimit"
)

// bandwidth consumption limiter
type bwCons struct {
	rl *ratelimit.Bucket
}

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
