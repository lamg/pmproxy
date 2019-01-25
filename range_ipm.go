package pmproxy

import (
	"net"
)

type rangeIPM struct {
	rg   *net.IPNet
	CIDR string `json:"cidr"`
	Name string `json:"name"`
}

func (m *rangeIPM) init() (e error) {
	_, m.rg, e = net.ParseCIDR(m.CIDR)
	return
}

const (
	rangeIPMT = "rangeIPM"
	cidrK     = "cidr"
)

func (r *rangeIPM) admin(c *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	if c.IsAdmin {
		cs = []cmdProp{
			{
				cmd:  get,
				prop: cidrK,
				f:    func() { fb([]byte(r.CIDR)) },
			},
			{
				cmd:  set,
				prop: cidrK,
				f: func() {
					r.CIDR = c.CIDR
					fe(r.init())
				},
			},
		}
	}
	return
}

func (r *rangeIPM) match(i string) (ok bool) {
	pip := net.ParseIP(ip)
	ok = pip != nil && m.rg.Contains(pip)
	return
}

func (r *rangeIPM) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK: r.Name,
		cidrK: r.CIDR,
	}
	tỹpe = rangeIPMT
	return
}

func (r *rangeIPM) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				r.Name, e = cast.ToStringE(i)
			},
		},
		{
			cidrK,
			func(i interface{}) {
				r.CIDR, e = cast.ToStringE(i)
			},
		},
		{
			cidrK, // if previous keys exists this exists and
			// r.init is executed
			func(i interface{}) {
				r.init()
			},
		},
	}
	mapKF(
		kf,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	return
}
