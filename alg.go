package pmproxy

// LS means Linear Search
func LS(b <-chan bool) (n int) {
	n = 0
	for !(<-b) {
		n = n + 1
	}
	return
}

// EqX b has the result of the equality test
// of every element in a with x
func EqX(a []int, x int, b chan<- bool) {
	for i := 0; i != len(a); i++ {
		b <- a[i] == x
	}
	return
}
