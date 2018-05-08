package pmproxy

import (
	"fmt"
	"github.com/gorilla/mux"
	h "net/http"
	"sync"
)

type CLMng struct {
	Name string `json:"name"`
	// ip-connection amount map
	am    *sync.Map
	Limit uint32 `json:"limit"`
}

func NewCLMng(name string, limit uint32) (c *CLMng) {
	c = &CLMng{
		Name:  name,
		Limit: limit,
		am:    new(sync.Map),
	}
	return
}

func (m *CLMng) PrefixHandler() (p *PrefixHandler) {
	p = &PrefixHandler{
		Prefix: "connection_limit",
	}
	rt, path := mux.NewRouter(), "/"+m.Name
	rt.HandleFunc(path, m.ChangeLimit).Methods(h.MethodPut)
	rt.HandleFunc(path, m.ServeLimit).Methods(h.MethodGet)
	p.Hnd = rt
	return
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

func (m *CLMng) Amount(addr string) (n uint32) {
	v, _ := m.am.Load(addr)
	n = v.(uint32)
	return
}

func (m *CLMng) ChangeLimit(w h.ResponseWriter, r *h.Request) {
	nl := uint32(0)
	_, e := fmt.Fscanf(r.Body, "%d", &nl)
	if e == nil {
		m.Limit = nl
	}
}

func (m *CLMng) ServeLimit(w h.ResponseWriter, r *h.Request) {
	fmt.Fprintf(w, "%d", m.Limit)
}
