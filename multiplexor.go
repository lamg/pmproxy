package pmproxy

// MultMsg multiplexes every first element of a slice of
// channels of messages
func MultMsg(mcs []chan string, mc chan<- string) {
	s, bc := make([]string, len(mcs)),
		make(chan bool, len(mcs)+1)
	for i := 0; i != len(s); i++ {
		s[i] = <-mcs[i]
		bc <- s[i] != ""
	}
	bc <- true
	// { sent len(s)+1 values to bc }
	for i := 0; i != len(mcs)+1; i++ {
		n := LS(bc)
		// { 0 <= n < len(s) || n = len(s)}
		if n+i != len(s) {
			mc <- s[n+i]
		} else {
			mc <- ""
		}
	}
}
