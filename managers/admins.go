package managers

import (
	alg "github.com/lamg/algorithms"
)

const ()

type admins struct {
	admins []string
}

func (m *admins) exec(c *Cmd) (term bool) {
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
	}
	alg.ExecF(kf, c.Cmd)
	return
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
