package managers

/*
# Administrators

Administrators is a manager implemented by `admins` that sets the field `Cmd.IsAdmin` according a list of administrators stored in it.

The `managerKF` method defines the `Cmd.IsAdmin` value, according the presence of the user that created it in the `admins.admins` slice, when `Cmd.Cmd = isAdminK`. If the value of `Cmd.User` isn't defined, then it leaves the command ready for `ipUser` to define that value.
*/

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
				if c.defined(userK) {
					c.IsAdmin, _ = alg.BLnSrch(
						func(i int) bool { return m.admins[i] == c.User },
						len(m.admins),
					)
					c.defKeys = append(c.defKeys, isAdminK)
					term = true
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
