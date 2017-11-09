package pmproxy

import (
	"time"
)

// MtTh associates a *ReqMatcher with the throttling
// interval and capacity
type MtTh struct {
	*ReqMatcher
	Intv time.Duration `json:"intv"`
	Cap  int64         `json:"cap"`
}

// TMng manages throttling
type TMng []MtTh

// ThrottSpec returns the throttling specification
func (t TMng) ThrottSpec(u *usrRC) (d time.Duration,
	c int64) {
	mt := make([]Matcher, len(t))
	for i, j := range t {
		mt[i] = j
	}
	b, i := BLS(mt, u)
	if b {
		d, c = t[i].Intv, t[i].Cap
	} else {
		// TODO define these values
		d, c = 0, 0
	}
	return
}
