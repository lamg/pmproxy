package pmproxy

type userIPM struct {
	IPUser string `json:"ipUser" toml: "ipUser"`
	iu     IPUser
	Users  []string `json:"users" toml: "users"`
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
