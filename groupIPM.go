package pmproxy

import (
	"encoding/json"
)

type groupIPM struct {
	ipg      ipGroup
	ipGroupN string
	name     string
	group    string
}

func (m *groupIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				m.name = stringE(i, fe)
			},
		},
		{
			ipGroupNK,
			func(i interface{}) {
				m.ipGroupN = stringE(i, fe)
			},
		},
		{
			groupK,
			func(i interface{}) {
				m.group = stringE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (m *groupIPM) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			set,
			func() {
				m.group = c.String
			},
		},
		{
			get,
			func() {
				c.bs, c.e = json.Marshal(m.toMap())
			},
		},
	}
	return
}

func (m *groupIPM) toMap() (i interface{}) {
	i = map[string]interface{}{
		groupK:    m.group,
		nameK:     m.name,
		ipGroupNK: m.ipGroupN,
	}
	return
}

func (m *groupIPM) match(ip string) (ok bool) {
	gs, _ := m.ipg(ip)
	ib := func(i int) (b bool) {
		b = m.group == gs[i]
		return
	}
	ok, _ = bLnSrch(ib, len(gs))
	return
}
