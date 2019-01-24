package pmproxy

import (
	"fmt"
	"github.com/lamg/clock"
	"log/syslog"
	"net"
	h "net/http"
)

type logger struct {
	cl     clock.Clock
	sl     *syslog.Writer
	iu     func(string) ipUser
	IPUser string `json:"ipUser"`
	Addr   string `json:"addr"`
}

func (l *logger) init() (e error) {
	if l.Addr != "" {
		l.sl, e = syslog.Dial("tcp", l.Addr, syslog.LOG_INFO, "")
	} else {
		l.sl, e = syslog.New(syslog.LOG_INFO, "")
	}
	return
}

func (l *logger) log(r *h.Request) (e error) {
	time := l.cl.Now()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	user := l.iu(l.IPUser)(clientIP)
	if user == "" {
		e = NoUserLogged(clientIP)
		user = "-"
	}
	// squid log format
	m := fmt.Sprintf(
		"%9d.000 %6d %s %s/%03d %d %s %s %s %s/%s %s",
		time.Unix(), 0, clientIP,
		"TCP_MISS", h.StatusOK, 0, r.Method, r.RequestURI, user,
		"DIRECT", "-", "-")
	if e == nil {
		e = l.sl.Info(m)
	} else {
		e = l.sl.Alert(m)
	}
	return
}

func NoUserLogged(ip string) (e error) {
	e = fmt.Errorf("No user logged at %s", ip)
	return
}
