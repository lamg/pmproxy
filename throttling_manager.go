package pmproxy

// MtTh associates a *ReqMatcher with the throttling
// interval and capacity
type MtTh struct {
	ResM []Predicate `json:"resM"`
	Frac float64     `json:"frac"`
}

// TMng manages throttling
type TMng []MtTh

// ThrottSpec returns the throttling specification
func (t TMng) ThrottSpec(u *usrRC) (f float64) {
	// match all MtTh
	b, i := BLS(j, u)
	if b {
		f = t[i].Frac1
	} else {
		f = 0
	}
	return
}
