package pmproxy

import (
	"fmt"
	. "net/http"
)

type PMSHandler struct {
	mx    *ServeMux
	sm    SessionManager
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

func (p *PMSHandler) Init(sm SessionManager, crypt Crypt) {
	p.mx, p.sm, p.crypt = NewServeMux(), sm, crypt
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
	ms ...string) (u *User, m int, ok bool) {
	m = 0
	for m != len(ms) && ms[m] != r.Method {
		m = m + 1
	}
	ok = m != len(ms)
	var msg []byte
	var st int
	if !ok {
		msg, st = []byte(
			fmt.Sprintf("Not supported method %s", r.Method)),
			StatusBadRequest
	}
	var scrt string
	if ok {
		// get user
		var e error
		scrt = r.Header.Get(jwtK)
		// decrypt scrt
		u, e = p.crypt.Decrypt(scrt)
		ok, st = e == nil, StatusOK
	}
	if !ok && msg == nil {
		msg, st = []byte(fmt.Sprintf("Invalid token %s", scrt)),
			StatusBadRequest
	}
	if !ok {
		w.Write(msg)
		w.WriteHeader(st)
	}
	return
}
