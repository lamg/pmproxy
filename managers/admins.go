package managers

import (
	alg "github.com/lamg/algorithms"
)

const ()

type admins struct {
	admins []string
}

func (m *admins) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			isAdmin,
			func() {
				c.IsAdmin, _ = alg.BLnSrch(
					func(i int) bool { return m.admins[i] == c.User },
					len(m.admins),
				)
			},
		},
		{Protect, func() { c.internal = true }},
	}
	alg.ExecF(kf, c.Cmd)
}

func (m *admins) paths() (ms []mngPath) {
	ms = []mngPath{
		{
			name: adminsMng,
			cmd:  isAdmin,
			mngs: []mngPath{
				{name: ipUserMng, cmd: Get},
				{name: adminsMng, cmd: isAdmin},
			},
		},
	}
	return
}
