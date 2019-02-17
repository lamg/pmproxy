package pmproxy

type auth func(string, string) (string, error)
type userGroup func(string) ([]string, error)

type userDB struct {
	name string
}

func (d *userDB) auth(user, pass string) (nuser string,
	e error) {
	return
}

func (d *userDB) userGroup(user string) (gs []string,
	e error) {
	return
}

func (d *userDB) userName(user string) (name string,
	e error) {
	return
}

func (d *userDB) fromMap(i interface{}) (e error) {
	return
}

func (d *userDB) toMap() (i interface{}) {
	return
}

func (d *userDB) managerKF() (kf []kFunc) {
	return
}
