package pmproxy

type userIPM struct {
	Name   string   `json:"name"`
	IPUser string   `json:"ipUser"`
	Users  []string `json:"users"`

	iu func(string) ipUser
}

func initUsrM(u *userIPM, si srchIU) (e error) {
	u.iu, e = si(u.NameF)
	return
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
	if cmd.IsAdmin && cmd.Cmd == "add" {
		u.Users = append(u.Users, cmd.User)
	} else if cmd.IsAdmin && cmd.Cmd == "del" {
		ib := func(i int) (b bool) {
			b = u.Users[i] == cmd.User
			return
		}
		b, i := bLnSrch(ib, len(u.Users))
		if !b {
			u.Users = append(u.Users[:i], u.Users[i+1:]...)
		}
	} else {
		e = NoCmd(cmd.Cmd)
	}
	return
}

func (u *userIPM) toSer() (tỹpe string, i interface{}) {
	return
}
