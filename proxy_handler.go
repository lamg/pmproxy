// TODO
package pmproxy

import (
	"net/http"
	"strings"
	"time"
)

type PrxHnd struct {
	l  Recorder
	rl ReqLim
}

func (q *PrxHnd) Init(rl ReqLim, l Recorder) {
	q.l, q.rl = l, rl
}

func (r *PrxHnd) ServeHTTP(w http.ResponseWriter,
	q *http.Request) {
	if q.RemoteAddr != "" {
		var ip string
		var e error
		var dt time.Time
		dt = time.Now()
		ip = strings.SplitN(q.RemoteAddr, ":", 2)[0]
		if r.rl.CanReq(ip, q.URL, dt) {
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
