package pmproxy

import (
	"log"
	"net"
	h "net/http"
	"strings"
	"time"
)

func writeLog(lg *log.Logger, r *h.Request, p *h.Response,
	user string, t time.Time) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)

	var cl int64  // response content length
	var ct string // response content type
	if p != nil {
		ct := p.Header.Get("Content-Type")
		sl := strings.Split(ct, ";")
		if len(sl) != 0 {
			ct = sl[0]
			// MIME type parameters dropped
		}
		cl = p.ContentLength
	}

	if ct == "" {
		ct = "-"
	}
	// Squid log format
	lg.Printf("%9d.000 %6d %s %s/%03d %d %s %s %s %s/%s %s",
		t.Unix(), 5*time.Millisecond, addr,
		"TCP_MISS", h.StatusOK, cl, r.Method,
		r.URL.String(), user, "DIRECT", "-", ct)
}
