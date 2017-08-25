package pmproxy

import (
	"fmt"
	"time"
)

// Structure produced by requests made to the proxy server
type Log struct {
	// Request's user
	User string
	// Client address
	Addr string
	// HTTP method
	Meth string
	// Accessed URI
	URI string
	// HTTP version
	Proto string
	// Response status code
	StatusCode int
	// Response size
	RespSize uint64
	// Response date-time
	Time time.Time
}

// TODO Returns a string with Squid log format
func (l *Log) String() (s string) {
	s = fmt.Sprintf("%s", l.User)
	return
}
