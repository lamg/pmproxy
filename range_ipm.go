package pmproxy

import (
	"encoding/json"
	"net"
)

type rangeIPM struct {
	rg   *net.IPNet
	name string
}

type jRangeIPM struct {
	CIDR string `json:"cidr"`
	Name string `json:"name"`
}

// json.Marshal implementation

func (m *rangeIPM) MarshalJSON() (bs []byte, e error) {
	jr := &jRangeIPM{
		CIDR: m.rg.String(),
		Name: m.name,
	}
	bs, e = json.Marshal(jr)
	return
}

// end

func newRangeIPM(cidr string, name string) (m *rangeIPM, e error) {
	m = &rangeIPM{
		name: name,
	}
	_, m.rg, e = net.ParseCIDR(cidr)
	return
}

func (m *rangeIPM) Match(ip string) (ok bool) {
	pip := net.ParseIP(ip)
	ok = pip != nil && m.rg.Contains(pip)
	return
}

func (m *rangeIPM) Name() (r string) {
	r = m.name
	return
}
