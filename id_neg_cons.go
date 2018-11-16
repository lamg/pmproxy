package pmproxy

// idCons always allows the consumption of the associated resource
type idCons struct {
	name string
}

// ConsR implementation

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

// end

// Admin implementation

func (d *idCons) Name() (r string) {
	r = d.name
	return
}

func (d *idCons) Exec(cmd *AdmCmd) (r string, e error) {
	return
}

// end

// negCons forbids the consumption of the associated resource
type negCons struct {
	name string
}

// ConsR implementation

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

// end

// Admin implementation

func (d *negCons) Name() (r string) {
	r = d.name
	return
}

func (d *negCons) Exec(cmd *AdmCmd) (r string, e error) {
	return
}

// end
