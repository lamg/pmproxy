package pmproxy

import (
	"github.com/juju/ratelimit"
)

// bandwidth consumption limiter
type bwCons struct {
	name string
	rl   *ratelimit.Bucket
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

// end

// Admin implementation

func (b *bwCons) Name() (r string) {
	r = b.name
	return
}

func (b *bwCons) Exec(cmd *AdmCmd) (r string, e error) {
	// the user must delete this manager,
	// instead of trying to change it
	return
}
