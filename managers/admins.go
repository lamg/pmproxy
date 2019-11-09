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
				c.isAdmin = m.isAdmin(c.loggedBy.user)
			},
		},
		{Protect, func() { c.internal = true }},
		{Get, func() { c.Info.IsAdmin = m.isAdmin(c.Info.UserName) }},
	}
	alg.ExecF(kf, c.Cmd)
}

func (m *admins) isAdmin(user string) (ok bool) {
	ok, _ = alg.BLnSrch(
		func(i int) bool { return m.admins[i] == user },
		len(m.admins),
	)
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
