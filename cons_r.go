package pmproxy

// consR stands for consumption restrictor,
// it restricts several aspects of a connection
type consR struct {
	open   func(ip) bool
	can    func(ip, download) bool
	update func(ip, download)
	close  func(ip)
}

type download int
type ip string

func idConsR() (c *consR) {
	c = &consR{
		Name: "idConsR",
		open: func(i ip) (ok bool) {
			ok = true
			return
		},
		can: func(i ip, d download) (ok bool) {
			ok = true
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
	}
	return
}

func negConsR() (c *consR) {
	c = &consR{
		Name: "negConsR",
		open: func(i ip) (ok bool) {
			ok = false
			return
		},
		can: func(i ip, d download) (ok bool) {
			ok = false
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
	}
	return
}
