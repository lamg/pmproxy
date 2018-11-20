package pmproxy

import "net"

type rangeIPM struct {
	rg   *net.IPNet
	name string
}

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
