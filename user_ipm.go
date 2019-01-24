package pmproxy

import (
	"github.com/spf13/cast"
)

type userIPM struct {
	Name   string   `json:"name"`
	IPUser string   `json:"ipUser"`
	Users  []string `json:"users"`

	iu func(string) ipUser
}

func (u *userIPM) match(ip string) (ok bool) {
	user := u.iu.User(ip)
	ok = user != ""
	if ok {
		ib := func(i int) (b bool) {
			b = user == u.Users[i]
			return
		}
		ok, _ = bLnSrch(ib, len(u.Users))
	}
	return
}

func (u *userIPM) admin(cmd *AdmCmd) (r []byte, e error) {
	if cmd.IsAdmin {
		kf := []kFunc{
			{
				add,
				func() {
					u.Users = append(u.Users, cmd.User)
				},
			},
			{
				del,
				func() {
					ib := func(i int) (b bool) {
						b = u.Users[i] == cmd.User
						return
					}
					b, i := bLnSrch(ib, len(u.Users))
					if !b {
						u.Users = append(u.Users[:i], u.Users[i+1:]...)
					}
				},
			},
		}
		exF(kf, cmd.Cmd, func(d error) { e = d })
	}
	return
}

const (
	userIPMT = "userIPM"
)

func (u *userIPM) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:   u.Name,
		ipUserK: u.IPUser,
		usersK:  u.Users,
	}
	tỹpe = userIPMT
	return
}

func (u *userIPM) fromMap(i interface{}) (e error) {
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				u.Name, e = cast.ToStringE(i)
			},
		},
		{
			ipUserK,
			func(i interface{}) {
				u.IPUser, e = cast.ToStringE(i)
			},
		},
		{
			usersK,
			func(i interface{}) {
				u.Users, e = cast.ToStringSliceE(i)
			},
		},
	}
	mapKF(
		fe,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	return
}
