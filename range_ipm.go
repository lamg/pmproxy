package pmproxy

import "net"

type rangeIPM struct {
	rg *net.IPNet
}

func newRangeIPM(cidr string) (m *rangeIPM, e error) {
	m = new(rangeIPM)
	_, m.rg, e = net.ParseCIDR(cidr)
	return
}

func (m *rangeIPM) Match(ip string) (ok bool) {
	pip := net.ParseIP(ip)
	ok = pip != nil && m.rg.Contains(pip)
	return
}
