package pmproxy

type mtIface struct {
	rm    *ReqMatcher
	iface string
}

// IMng manages interfaces
type IMng struct {
	ih []mtIface
}

// Interface returns the interface associated to
// the request
func (m *IMng) Interface(r *usrRC) (s string) {
	i, b := 0, false
	for !b && i != len(m.ih) {
		b = m.ih[i].rm.Match(r)
		if !b {
			i = i + 1
		}
	}
	// { bounded linear search with ReqMatcher.Match
	//	 as predicate }
	if b {
		s = m.ih[i].iface
	}
	return
}
