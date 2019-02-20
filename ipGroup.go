package pmproxy

type ipGroupS struct {
	ipUser     ipUser
	userGroupN string
	userGroup  func(string) (userGroup, bool)
}

type ipGroup func(string) ([]string, error)

func (p *ipGroupS) get(ip string) (gs []string, e error) {
	var user string
	var ok bool
	var grp userGroup
	fs := []func(){
		func() { user, ok = p.ipUser(ip) },
		func() { grp, ok = p.userGroup(p.userGroupN) },
		func() { gs, e = grp(user) },
	}
	trueFF(fs, func() bool { return ok && e == nil })
	return
}
