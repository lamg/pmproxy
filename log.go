package pmproxy

import (
	"fmt"
	"time"
)

// Log is the struct produced by requests made to the proxy server
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
	// Elapsed time between request received and response sent
	Elapsed time.Duration
	// How the request was treated locally
	Action string
	// How and where the requested object was fetched.
	Hierarchy string
	// Hostname of the machine where we got the object
	From string
	// Content type from HTTP header
	ContentType string
}

// time elapsed remotehost code/status bytes method URL rfc931 peerstatus/peerhost type
func (l *Log) String() (s string) {
	s = fmt.Sprintf(
		"%9d.000 %6d %s %s/%03d %d %s %s %s %s/%s %s",
		l.Time.Unix(), l.Elapsed, l.Addr,
		l.Action, l.StatusCode, l.RespSize, l.Meth, l.URI, l.User,
		l.Hierarchy, l.From, l.ContentType)
	return
}
