package pmproxy

import (
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
)

// trCons is a time range consumption limiter for a connection
type trCons struct {
	clock clock.Clock
	span  *rt.RSpan
}

func (t *trCons) Can(ip string, n int) (ok bool) {
	tm := t.clock.Now()
	ok = t.span.ContainsTime(tm)
	return
}

func (t *trCons) UpdateCons(ip string, n int) {

}

func (t *trCons) Close(ip string) {

}
