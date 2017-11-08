package pmproxy

// mtCfQt associates a ReqMatcher with consumption
// coeficient and quota
type mtCfQt struct {
	rm *ReqMatcher
	k  float32
	t  uint64
}

// QMng manages quotas
type QMng struct {
	// Hierarchy of coeficients and quotas.
	// mtCfQt associations with lower index are higher
	// in the hierarchy.
	qh []mtCfQt

	// TODO define hierarchy of quotas
}

// Quota determines the coeficient and quota
func (q *QMng) Quota(u *usrRC) (k float32, t uint64) {
	i, b := 0, false
	for !b && i != len(q.qh) {
		b = q.qh[i].rm.Match(u)
		if !b {
			i = i + 1
		}
	}
	// { bounded linear search with ReqMatcher.Match as
	// predicate }
	if b {
		k, t = q.qh[i].k, q.qh[i].t
	} else {
		// { not found }
		k, t = -1, 0
		// { access forbidden }
	}
	return
}
