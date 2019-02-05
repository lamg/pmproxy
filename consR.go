package pmproxy

// consR stands for consumption restrictor,
// it restricts several aspects of a connection
type consR struct {
	open   func(string) bool
	can    func(string, int) bool
	update func(string, int)
	close  func(string)
}

func idConsR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			ok = true
			return
		},
		can: func(ip string, down int) (ok bool) {
			ok = true
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}

func negConsR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			ok = false
			return
		},
		can: func(ip string, down int) (ok bool) {
			ok = false
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}

func readConsR() (s *sync.Map, e error) {
	sl := viper.Get("downCons")
	// TODO
	return
}
