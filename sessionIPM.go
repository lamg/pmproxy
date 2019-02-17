package pmproxy

type sessionIPM struct {
	name     string
	ipUser   *ipUserS
	nameAuth func(string) (auth, bool)
}

func (m *sessionIPM) fromMap(i interface{}) (e error) {
	return
}

func (m *sessionIPM) managerKF() (kf []kFunc) {
	return
}

func (m *sessionIPM) match(ip string) (ok bool) {
	return
}

func (m *sessionIPM) toMap() (i interface{}) {
	return
}
