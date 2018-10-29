package pmproxy

// bandwidth consumption limiter
type bwCons struct {
}

func (b *bwCons) Can(ip string, n int) (ok bool) {
	ok = true
	return
}

func (b *bwCons) UpdateCons(ip string, n int) {
	return
}

func (b *bwCons) Close(ip string) {

}
