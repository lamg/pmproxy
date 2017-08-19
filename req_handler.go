package pmproxy

import (
	"net/http"
	"strings"
	"time"
)

type ReqHandler struct {
	l  RequestLogger
	qu QuotaUser
	// register of TCP tunnels (client, server)
	tcpCn map[string]string
}

func (q *ReqHandler) Init(qu QuotaUser, l RequestLogger) {
	q.qu, q.l = qu, l
}

func (r *ReqHandler) ServeHTTP(w http.ResponseWriter,
	q *http.Request) {
	if q.RemoteAddr != "" {
		var ip IP
		var e error
		ip = IP(strings.SplitN(q.RemoteAddr, ":", 2)[0])
		if r.qu.CanReq(ip, q.URL) {
			var dt time.Time
			dt = time.Now()
			//make request
			var p *http.Response
			// TODO is this correct for HTTPS tunneling?
			p, e = http.DefaultClient.Do(q)
			if e == nil {
				r.qu.AddConsumption(ip, uint64(p.ContentLength))
				//log response
				r.l.LogRes(ip, q.URL.String(), q.Method, q.Proto,
					p.StatusCode, uint64(p.ContentLength), dt)
				//write response
				p.Write(w)
			}
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}
