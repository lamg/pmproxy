package pmproxy

import (
	"fmt"
)

func noKey(k string) (e error) {
	e = fmt.Errorf("No key %s", k)
	return
}

func noUserLogged(ip string) (e error) {
	e = fmt.Errorf("No user logged at %s", ip)
	return
}

func cannotConsume(raddr string) (e error) {
	e = fmt.Errorf("Cannot consume %s", raddr)
	return
}

func cannotOpen(raddr string) (e error) {
	e = fmt.Errorf("Cannot open connection from %s", raddr)
	return
}

// NotLocalIP is the not found local IP address error
func noLocalIP() (e error) {
	e = fmt.Errorf("Not found local IP address")
	return
}

func noSpecValue() (e error) {
	e = fmt.Errorf("Value isn't of type *specV")
	return
}

func noSpecKey(sk specKT) (e error) {
	e = fmt.Errorf("No spec key %s found", sk)
	return
}

func needXServers(x, n int) (e error) {
	e = fmt.Errorf("Need %d servers, not %d", x, n)
	return
}

func invalidSpec(s *spec) (e error) {
	e = fmt.Errorf("Invalid spec: %v", s)
	return
}

func indexOutOfRange(i, n int) (e error) {
	e = fmt.Errorf("Not 0 ≤ %d < %d", i, n)
	return
}

func invalidPos(pos []int) (e error) {
	e = fmt.Errorf("Invalid positions %v", pos)
	return
}
