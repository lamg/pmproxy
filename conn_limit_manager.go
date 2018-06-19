package pmproxy

import (
	"fmt"
	h "net/http"
	"sync"

	"github.com/gorilla/mux"
)

// CLMng is the connection limit manager. It limits the number of
// connections made from one IP address.
type CLMng struct {
	Name string `json:"name"`
	// ip-connection amount map
	am    *sync.Map
	Limit uint32 `json:"limit"`
}

// NewCLMng returns a new CLMng
func NewCLMng(name string, limit uint32) (c *CLMng) {
	c = &CLMng{
		Name:  name,
		Limit: limit,
		am:    new(sync.Map),
	}
	return
}

// PrefixHandler returns an h.Handler for interacting with CLMng
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

// AddConn increases the connection amount from addr
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

// DecreaseAm decreases the connection amount from addr
func (m *CLMng) DecreaseAm(addr string) {
	v, ok := m.am.Load(addr)
	if ok {
		n := v.(uint32)
		n = n - 1
		m.am.Store(addr, n)
	}
}

// Amount returns the connection amount from addr
func (m *CLMng) Amount(addr string) (n uint32) {
	v, _ := m.am.Load(addr)
	n = v.(uint32)
	return
}

// ChangeLimit is an h.Handler for changing the maximum amount of
// connections from one IP address
func (m *CLMng) ChangeLimit(w h.ResponseWriter, r *h.Request) {
	nl := uint32(0)
	_, e := fmt.Fscanf(r.Body, "%d", &nl)
	if e == nil {
		m.Limit = nl
	}
}

// ServeLimit is an h.Handler that shows the current maximum connection
// amount
func (m *CLMng) ServeLimit(w h.ResponseWriter, r *h.Request) {
	fmt.Fprintf(w, "%d", m.Limit)
}
