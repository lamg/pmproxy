package pmproxy

import (
	"net"
)

type rangeIPM struct {
	rg   *net.IPNet
	CIDR string `json:"cidr"`
	Name string `json:"name"`
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
	return
}

func (r *rangeIPM) manager() (m *manager) {
	m = &manager{
		name: r.Name,
		tỹpe: "rangeIPM",
		cons: idConsR(),
		adm: func(c *AdmCmd) (bs []byte, e error) {
			switch c.Cmd {
			case "get-cidr":
				bs = []byte(r.CIDR)
			case "set-cidr":
				r.CIDR = c.CIDR
				e = m.init()
			default:
				e = NoCmd(c.Cmd)
			}
			return
		},
		mtch: func(i string) (ok bool) {
			pip := net.ParseIP(ip)
			ok = pip != nil && m.rg.Contains(pip)
			return
		},
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK: r.Name,
				cidrK: r.CIDR,
			}
			return
		},
	}
	return
}
