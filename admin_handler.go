package pmproxy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	. "net/http"
)

type PMAdmin struct {
	mx *ServeMux
	ui UserInf
	qa QuotaAdmin
}

const (
	// POST, DELETE
	logX       = "/logX"
	groupQuota = "/groupQuota"
	userGroup  = "/userGroup"
	userCons   = "/userCons"
	authHd     = "authHd"
)

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (p *PMAdmin) Init(qa QuotaAdmin) {
	p.qa, p.mx = qa, NewServeMux()
	p.mx.HandleFunc(logX, p.logXHF)
	p.mx.HandleFunc(groupQuota, p.groupQuotaHF)
	p.mx.HandleFunc(userGroup, p.userGroupHF)
	p.mx.HandleFunc(userCons, p.userConsHF)
	// TODO implement routes
}

func (p *PMAdmin) logXHF(w ResponseWriter, r *Request) {
	var e error
	var scrt string
	if r.Method == MethodPost {
		cr := new(Credentials)
		var bs []byte
		bs, e = ioutil.ReadAll(r.Body)
		if e == nil {
			e = json.Unmarshal(bs, cr)
		}
		if e == nil {
			scrt, e = p.qa.Login(Name(cr.User), IP(r.RemoteAddr),
				cr.Pass)
		}
		if e == nil {
			w.Header()[authHd] = []string{scrt}
		}
	} else if r.Method == MethodDelete {
		scrt, e = getScrt(r.Header)
		if e == nil {
			e = p.qa.Logout(scrt)
		}
	}
	// write error
}

func (p *PMAdmin) userGroupHF(w ResponseWriter, r *Request) {
	// s, e := getScrt(r.Header)
	// TODO
}

func (p *PMAdmin) groupQuotaHF(w ResponseWriter, r *Request) {

}

func (p *PMAdmin) userConsHF(w ResponseWriter, r *Request) {

}

func (p *PMAdmin) ServeHTTP(w ResponseWriter, r *Request) {
	p.mx.ServeHTTP(w, r)
}

func getScrt(h Header) (s string, e error) {
	sl, ok := h[authHd]
	if !ok || len(s) != 1 {
		e = fmt.Errorf("Malformed header")
	} else {
		s = sl[0]
	}
	return
}
