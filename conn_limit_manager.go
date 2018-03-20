package pmproxy

import (
	"sync"
)

type CLMng struct {
	// ip-connection amount map
	am    *sync.Map
	Limit uint32
}

func (m *CLMng) AddConn(addr string) (b bool) {
	v, ok := m.am.Load(addr)
	var n uint32
	if ok {
		n = v.(uint32)
		n = n + 1
	}
	b = n <= m.Limit
	if b {
		m.am.Store(addr, n)
	}
	return
}

func (m *CLMng) DecreaseAm(addr string) {
	v, ok := m.am.Load(addr)
	if ok {
		n := v.(uint32)
		n = n - 1
		m.am.Store(addr, n)
	}
}

func (m *CLMng) GetAmount(addr string) (n uint32) {
	v, _ := m.am.Load(addr)
	n = v.(uint32)
	return
}
