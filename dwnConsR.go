package pmproxy

type dwnConsR struct {
	name     string
	ipQuotaN string
	ipq      func(string) uint64
}

func (d *dwnConsR) fromMap(i interface{}) (e error) {
	return
}

func (d *dwnConsR) managerKF(c *cmd) (kf []kFunc) {
	return
}

func (d *dwnConsR) consR() (c *consR) {
	return
}

func (d *dwnConsR) toMap() (i interface{}) {
	return
}
