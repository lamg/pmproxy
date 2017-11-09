package pmproxy

// MtIface associates a *ReqMatcher with a network
// interface name
type MtIface struct {
	*ReqMatcher
	Iface string `json:"iface"`
}

// IMng manages interfaces
type IMng []MtIface

// Interface returns the interface associated to
// the request
func (m IMng) Interface(r *usrRC) (s string) {
	mt := make([]Matcher, len(m))
	for i, j := range m {
		mt[i] = j
	}
	b, i := BLS(mt, r)
	if b {
		s = m[i].Iface
	}
	return
}
