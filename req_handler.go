package main

import (
	"net/http"
)

type ReqHandler struct {
	l  LogRes
	qu QuotaUser
}

func NewReqHandler(l LogRes, qu QuotaUser) (r *ReqHandler) {
	r = &ReqHandler{l, qu}
	return
}

func (r *ReqHandler) Handle(w http.ResponseWriter,
	q *http.Request) {
	if q.RemoteAddr != "" {
		var ip IP
		ip = strings.SplitN(q.RemoteAddr, ":", 2)[0]
		var user Name
		user = r.qu.GetUserName(ip)
		if r.qu.CanReq(user) {
			//make request
			var p *http.Response
			if q.Method == http.METHOD_CONNECT {
			} else {
			}
			if e == nil {
				r.qu.SetUserConsumption(r.qu.GetUserConsumption(user) +
					uint64(p.ContentLength))
				//log response
				//write response
			}
		}
	} else {
		//invalid request
	}
}
