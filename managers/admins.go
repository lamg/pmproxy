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

func (m *admins) managerKF(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			isAdminK,
			func() {
				if c.defined(userK) {
					// TODO
				} else {
					c.Manager, c.Cmd = ipUserMng, Get
				}
			},
		},
	}
	// TODO
	alg.ExecF(kf, c.Cmd)
	return
}
