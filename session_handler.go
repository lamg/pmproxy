package pmproxy

import (
	"fmt"
	. "net/http"
)

type PMSHandler struct {
	mx    *ServeMux
	sm    SessionManager
	qu    QuotaUser
	qa    QuotaAdministrator
	crypt Crypt
}

const (
	//GET,PUT
	groupQuota = "/group_quota"
	//GET,PUT
	userQuota = "/user_quota"
	//POST,DELETE
	userLog = "/user_log"
	//POST
	addCns = "/add_cns"

	jwtK = "jwtK"
)

func (p *PMSHandler) Init(crypt Crypt, sm SessionManager,
	qu QuotaUser, qa QuotaAdministrator) {
	p.mx, p.sm, p.crypt, p.qu, p.qa =
		NewServeMux(), crypt, sm, qu, qa
	//add handlers for user and admin session
	p.mx.HandleFunc(groupQuota, p.groupQuotaH)
	p.mx.HandleFunc(userQuota, p.userQuotaH)
	p.mx.HandleFunc(userLog, p.userLogH)
	p.mx.HandleFunc(addCns, p.addCnsH)
}

func (p *PMSHandler) ServeHTTP(w ResponseWriter, r *Request) {
	p.mx.ServeHTTP(w, r)
}

func (p *PMSHandler) groupQuotaH(w ResponseWriter, r *Request) {
	var u *User
	var meth int
	var ok bool
	u, meth, ok = p.gUsrMth(r, w, MethodGet, MethodPut)
	if ok && meth == 0 {
	} else if ok && meth == 1 && u.IsAdmin {
	}
}

func (p *PMSHandler) userQuotaH(w ResponseWriter, r *Request) {
	var u *User
	var meth int
	var ok bool
	u, meth, ok = p.gUsrMth(r, w, MethodGet, MethodPut)
	if ok && meth == 0 {
	} else if ok && meth == 1 && u.IsAdmin {
	}
}

func (p *PMSHandler) adminLogH(w ResponseWriter, r *Request) {
	var u *User
	var meth int
	var ok bool
	u, meth, ok = p.gUsrMth(r, w, MethodPost, MethodDelete)
	if ok && meth == 0 {
	} else if ok && meth == 1 && u.IsAdmin {
	}
}

func (p *PMSHandler) userLogH(w ResponseWriter, r *Request) {
	var u *User
	var meth int
	var ok bool
	u, meth, ok = p.gUsrMth(r, w, MethodPost, MethodDelete)
	if ok && meth == 0 {
	} else if ok && meth == 1 && u.IsAdmin {
	}
}

func (p *PMSHandler) addCnsH(w ResponseWriter, r *Request) {
	var ok bool
	_, _, ok = p.gUsrMth(r, w, MethodPost)
	if ok {
	}
}

func (p *PMSHandler) gUsrMth(r *Request, w ResponseWriter,
	ms ...string) (u *User, m int, e error) {
	m = 0
	for m != len(ms) && ms[m] != r.Method {
		m = m + 1
	}
	if m == len(ms) {
		e = fmt.Errorf("Not supported method %s", r.Method)
	}
	if e == nil {
		var scrt string
		scrt = r.Header.Get(jwtK)
		u, e = p.crypt.Decrypt(scrt)
	}
	if e != nil {
		w.Write(e.Error())
		w.WriteHeader(StatusBadRequest)
	}
	return
}
