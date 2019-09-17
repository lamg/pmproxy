package managers

import (
	alg "github.com/lamg/algorithms"
)

const (
	isAdminK  = "isAdmin"
	adminsMng = "adminsMng"
)

type admins struct {
	admins []string
}

func (m *admins) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			isAdminK,
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
			cmd:  isAdminK,
			mngs: []mngPath{
				{name: ipUserMng, cmd: Get},
				{name: adminsMng, cmd: isAdminK},
			},
		},
	}
	return
}
