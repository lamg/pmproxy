package pmproxy

import (
	"encoding/json"
	"sync"
)

// MtCfQt associates a ReqMatcher with consumption
// coeficient and quota
type MtCfQt struct {
	Predicate `json:"resM"`
	// Consumption coeficient
	Coeficient float32 `json:"coeficient"`
	// Quota
	Total   uint64 `json:"total"`
	usrCons *sync.Map
	UsrCons map[string]uint64 `json:"usrCons"`
}

// UnmarshalJSON is the json.Unmarshaler implementation
func (m *MtCfQt) UnmarshalJSON(p []byte) (e error) {
	e = json.Unmarshal(p, m)
	if e == nil {
		for k, v := range m.UsrCons {
			m.usrCons.Store(k, v)
		}
	}
	return
}

// MarshalJSON is the json.Marshaler implementation
func (m *MtCfQt) MarshalJSON() (p []byte, e error) {
	m.UsrCons = make(map[string]uint64)
	m.usrCons.Range(func(k, v interface{}) (y bool) {
		ks, vu := k.(string), v.(uint64)
		m.UsrCons[ks] = vu
		return
	})
	p, e = json.Marshal(m)
	return
}

func (m *MtCfQt) incCons(user string, c uint64) (y bool) {
	v, ok := m.usrCons.Load(user)
	if !ok {
		v = 0
	}
	vu := v.(uint64) + c
	y = m.Coeficient >= 0 && vu <= m.Total
	if y {
		vu = uint64(m.Coeficient * float32(vu))
		m.usrCons.Store(user, vu)
	}
	return
}
