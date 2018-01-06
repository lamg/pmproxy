package pmproxy

import (
	h "net/http"
	"time"
)

// ResDet determines a string identifying a
// resource
type ResDet interface {
	Det(*h.Request, time.Time, string) string
}
