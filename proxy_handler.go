package pmproxy

import (
	"net/http"
	"strings"
	"time"
)

type ReqHandler struct {
	iu IPUser
	l  Recorder
	rl ReqLim
}

func (q *ReqHandler) Init(iu IPUser, rl ReqLim, l Recorder) {
	q.iu, q.l, q.rl = iu, l, rl
}

func (r *ReqHandler) ServeHTTP(w http.ResponseWriter,
	q *http.Request) {
	if q.RemoteAddr != "" {
		var ip IP
		var usr Name
		var e error
		var dt time.Time
		dt = time.Now()
		ip = IP(strings.SplitN(q.RemoteAddr, ":", 2)[0])
		usr = r.iu.UserName(ip)
		if r.rl.CanReq(usr, q.URL, dt) {
			//make request
			var p *http.Response
			// TODO is this correct for HTTPS tunneling?
			p, e = http.DefaultClient.Do(q)
			if e == nil {
				//log response
				var lg *Log
				lg = &Log{
					Addr:       ip,
					Meth:       q.Method,
					Proto:      p.Proto,
					RespSize:   uint64(p.ContentLength),
					StatusCode: p.StatusCode,
					Time:       dt,
					URI:        q.URL.String(),
					User:       usr,
				}
				r.l.Record(lg)
				//write response
				p.Write(w)
			}
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}
}
