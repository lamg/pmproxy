package pmproxy

type groupIPM struct {
	ipgs *ipGroupS
	name string
}

func (m *groupIPM) fromMap(i interface{}) (e error) {
	return
}

func (m *groupIPM) ipGroup(ip string) (gs []string,
	e error) {
	return
}

func (m *groupIPM) managerKF(c *cmd) (kf []kFunc) {
	return
}

func (m *groupIPM) toMap() (i interface{}) {
	return
}

func (m *groupIPM) match(ip string) (ok bool) {
	return
}
