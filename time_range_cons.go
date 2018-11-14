package pmproxy

import (
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
)

// trCons is a time range consumption limiter for a connection
type trCons struct {
	name  string
	clock clock.Clock
	span  *rt.RSpan
}

// ConsR implementation

func (t *trCons) Open(ip string) (ok bool) {
	tm := t.clock.Now()
	ok = t.span.ContainsTime(tm)
	return
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

// end

// Admin implementation

func (t *trCons) Name() (r string) {
	r = t.name
	return
}

func (t *trCons) Exec(cmd *AdmCmd) (r string, e error) {
	// TODO
	// probably doing nothing here is a good option since the user
	// can delete this manager and add the one he needs
	return
}

// end
