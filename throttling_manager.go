package pmproxy

import (
	"time"
)

type mtTh struct {
	rm   *ReqMatcher
	intv time.Duration
	cap  int64
}

// TMng manages throttling
type TMng struct {
	th []mtTh
}

// ThrottSpec returns the throttling specification
func (t *TMng) ThrottSpec(u *usrRC) (d time.Duration,
	c int64) {

	return
}
