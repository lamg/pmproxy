package pmproxy

// ReqMatcher matches requests
type ReqMatcher struct {
	// Group-time
	// RemoteAddr-time
	// Host-time
	// User-time
}

// Match does de actual matching
func (r *ReqMatcher) Match(u *usrRC) (y bool) {
	return
}

// Matcher is an interface for matching *usrRC
type Matcher interface {
	Match(*usrRC) bool
}

// BLS is the Bounded Linear Search algorithm, using
// Matcher.Match as predicate
func BLS(ms []Matcher, u *usrRC) (b bool,
	i int) {
	b, i = false, 0
	for !b && i != len(ms) {
		b = ms[i].Match(u)
		if !b {
			i = i + 1
		}
	}
	return
}
