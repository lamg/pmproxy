package pmproxy

import (
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
)

// trCons is a time range consumption limiter for a connection
type trCons struct {
	NameF string `json:"name"`
	clock clock.Clock
	Span  *rt.RSpan `json:"span"`
}

// ConsR implementation

func (t *trCons) Open(ip string) (ok bool) {
	tm := t.clock.Now()
	ok = t.Span.ContainsTime(tm)
	return
}

func (t *trCons) Can(ip string, n int) (ok bool) {
	tm := t.clock.Now()
	ok = t.Span.ContainsTime(tm)
	return
}

func (t *trCons) UpdateCons(ip string, n int) {

}

func (t *trCons) Close(ip string) {

}

func (t *trCons) Name() (r string) {
	r = t.NameF
	return
}

// end

// Admin implementation

func (t *trCons) Exec(cmd *AdmCmd) (r string, e error) {
	// probably doing nothing here is a good option since the user
	// can delete this manager and add the one he needs
	return
}

// end
