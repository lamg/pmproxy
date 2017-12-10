package pmproxy

// MultMsg multiplexes a slice of channels of messages
func MultMsg(mcs []chan string, mc chan<- string) {
	s, bc := make([]string, len(mcs)), make(chan bool)
	for i := 0; i != len(s); i++ {
		s[i] = <-mcs[i]
		bc <- s[i] != ""
	}
	bc <- true
	// { sent len(s)+1 values to bc }
	n := LS(bc)
	// { 0 <= n < len(s) || n = len(s)}
	if n != len(s) {
		mc <- s[n]
	} else {
		mc <- ""
	}
}
