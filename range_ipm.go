package pmproxy

import (
	"encoding/json"
	"net"
)

type rangeIPM struct {
	rg    *net.IPNet
	CIDR  string `json:"cidr" toml:"cidr"`
	NameF string `json:"name" toml:"name"`
}

func newRangeIPM(cidr string, name string) (m *rangeIPM, e error) {
	m = &rangeIPM{
		CIDR:  cidr,
		NameF: name,
	}
	e = m.init()
	return
}

func (m *rangeIPM) init() (e error) {
	_, m.rg, e = net.ParseCIDR(m.CIDR)
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

func (m *rangeIPM) Admin(cmd *AdmCmd) (r strin, e error) {
	return
}
