package pmproxy

type userIPM struct {
	NameF  string   `json:"name" toml:"name"`
	IPUser string   `json:"ipUser" toml:"ipUser"`
	Users  []string `json:"users" toml:"users"`

	iu IPUser
}

func (u *userIPM) Match(ip string) (ok bool) {
	user := u.iu.User(ip)
	ok = false
	if user != "" {
		i := 0
		for !ok && i != len(u.Users) {
			ok, i = user == u.Users[i], i+1
		}
	}
	return
}

func (u *userIPM) Name() (r string) {
	r = u.NameF
	return
}

func (u *userIPM) Exec(cmd *AdmCmd) (r string, e error) {
	if cmd.Cmd == "add" {
		u.Users = append(u.Users, cmd.User)
	} else if cmd.Cmd == "del" {
		i, b := 0, true
		for b && i != len(u.Users) {
			b = u.Users[i] != cmd.User
			if b {
				i = i + 1
			}
		}
		if !b {
			u.Users = append(u.Users[:i], u.Users[i+1:]...)
		}
	} else {
		e = NoCmd(cmd.Cmd)
	}
	return
}
