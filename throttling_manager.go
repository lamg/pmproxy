package pmproxy

// MtTh associates a *ReqMatcher with the throttling
// interval and capacity
type MtTh struct {
	*ReqMatcher
	Frac float64 `json:"frac"`
}

// TMng manages throttling
type TMng []MtTh

// ThrottSpec returns the throttling specification
func (t TMng) ThrottSpec(u *usrRC) (f float64) {
	mt := make([]Matcher, len(t))
	for i, j := range t {
		mt[i] = j
	}
	b, i := BLS(mt, u)
	if b {
		f = t[i].Frac
	} else {
		f = 0
	}
	return
}
