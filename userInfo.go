package pmproxy

import (
	"encoding/json"
)

type userInfo struct {
	iu       ipUser
	userName func(string) (string, error)
	quota    ipQuota
	isAdm    func(string) bool
}

type cmdInfo struct {
	UserName   string `json: "userName"`
	Name       string `json: "name"`
	IsAdmin    bool   `json: "isAdmin"`
	QuotaGroup uint64 `json: "quotaGroup"`
}

func (u *userInfo) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				user := u.iu(c.RemoteAddr)
				inf := &cmdInfo{
					UserName:   user,
					IsAdmin:    u.isAdm(user),
					QuotaGroup: u.quota(user),
				}
				fs := []func(){
					func() { inf.Name, c.e = u.userName(user) },
					func() { c.bs, c.e = json.Marshal(inf) },
				}
				trueFF(fs, func() bool { return c.e == nil })
			},
		},
	}
	return
}
