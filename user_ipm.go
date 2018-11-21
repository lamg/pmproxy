package pmproxy

type userIPM struct {
	iu    IPUser   `json:"iu"`
	Users []string `json:"users"`
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
