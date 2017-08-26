package main

import (
	. "net/http"
)

const (
	// POST, DELETE
	logX = "/logX"
	// POST, PUT
	groupQuota = "/groupQuota"
	// POST
	userCons = "/userCons"
	authHd   = "authHd"
)

type PMProxy struct {
	mx *ServeMux
	qa *QAdm
}

func Init(qa *QAdm) {
	p.qa, p.mx = qa, NewServeMux()
	p.mx.HandleFunc(logX, p.logXHF)
	p.mx.HandleFunc(groupQuota, p.groupQuotaHF)
	p.mx.HandleFunc(userCons, p.userConsHF)
}

func (p *PMProxy) logXHF(w ResponseWriter, r *Request) {
	var e error
	var scrt string
	if r.Method == MethodPost {
		cr := new(Credentials)
		e = decode(r.Body, cr)
		if e == nil {
			scrt, e = p.qa.Login(cr, r.RemoteAddr)
		}
		if e == nil {
			w.Header()[authHd] = []string{scrt}
		}
	} else if r.Method == MethodDelete {
		scrt, e = getScrt(r.Header)
		if e == nil {
			e = p.qa.Logout(scrt)
		}
	} else {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *PMProxy) groupQuotaHF(w ResponseWriter, r *Request) {
	s, e := getScrt(r.Header)
	gr := new(GroupQuota)
	if r.Method == MethodPost {
		e = decode(r.Body, gr)
		if e == nil {
			p.qa.GetQuota(s, gr)
			e = encode(w, gr)
		}
	} else if r.Method == MethodPut {
		e = decode(r.Body, gr)
		if e == nil {
			p.qa.SetQuota(s, gr)
		}
	} else {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *PMProxy) userConsHF(w ResponseWriter, r *Request) {
	s, e := getScrt(r.Header)
	usr := new(User)
	if r.Method == MethodPost {
		e = decode(r.Body, usr)
	} else {
		e = notSuppMeth(r.Method)
	}
	if e == nil {
		p.qa.UserCons(s, usr)
		e = encode(w, usr)
	}
	writeErr(w, e)
}

func (p *PMProxy) ServeHTTP(w ResponseWriter, r *Request) {
	if r.URL.Host == "" {
		p.mx.ServeHTTP(w, r)
	} else {
		p.Proxy(w, r)
	}
}

func (p *PMProxy) Proxy(w ResponseWriter, r *Request) {

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

func decode(r io.Reader, v interface{}) (e error) {
	var bs []byte
	bs, e = ioutil.ReadAll(r)
	if e == nil {
		e = json.Unmarshal(bs, v)
	}
	return
}

func encode(w io.Writer, v interface{}) (e error) {
	var bs []byte
	bs, e = json.Marshal(v)
	if e == nil {
		_, e = w.Write(bs)
	}
	return
}

func writeErr(w ResponseWriter, e error) {
	w.Write([]byte(e.Error()))
	w.WriteHeader(StatusBadRequest)
}

func notSuppMeth(m string) (e error) {
	e = fmt.Errorf("Not supported method %s", m)
	return
}
