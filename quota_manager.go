package pmproxy

// MtCfQt associates a ReqMatcher with consumption
// coeficient and quota
type MtCfQt struct {
	*ReqMatcher
	// Consumption coeficient
	K float32 `json:"k"`
	// Quota
	T uint64 `json:"t"`
}

// QMng manages quotas
type QMng []MtCfQt

// Quota determines the coeficient and quota
func (q QMng) Quota(u *usrRC) (k float32, t uint64) {
	mc := make([]Matcher, len(q))
	for i, j := range q {
		mc[i] = j
	}
	b, i := BLS(mc, u)
	if b {
		k, t = q[i].K, q[i].T
	} else {
		// { not found }
		k, t = -1, 0
		// { access forbidden }
	}
	return
}
