package pmproxy

type userIPM struct {
	iu    IPUser
	users []string
}

func (u *userIPM) Match(ip string) (ok bool) {
	user := u.iu.User(ip)
	ok = false
	if user != "" {
		i := 0
		for !ok && i != len(u.users) {
			ok, i = user == u.users[i], i+1
		}
	}
	return
}
