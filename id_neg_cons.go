package pmproxy

// idCons always allows the consumption of the associated resource
type idCons struct {
}

func (d *idCons) Open(ip string) (ok bool) {
	ok = true
	return
}

func (d *idCons) Can(ip string, n int) (ok bool) {
	ok = true
	return
}

func (d *idCons) UpdateCons(ip string, n int) {

}

func (d *idCons) Close(ip string) {

}

// negCons forbids the consumption of the associated resource
type negCons struct {
}

func (d *negCons) Open(ip string) (ok bool) {
	ok = false
	return
}

func (d *negCons) Can(ip string, n int) (ok bool) {
	ok = false
	return
}

func (d *negCons) UpdateCons(ip string, n int) {

}

func (d *negCons) Close(ip string) {

}
