package pmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	. "net/http"
)

const (
	// POST, DELETE
	logX = "/logX"
	// GET, PUT
	groupQuota = "/groupQuota"
	// GET
	userCons = "/userCons"
	// GET, POST
	accExcp = "/accessExceptions"
	authHd  = "authHd"
	userV   = "user"
	groupV  = "group"
)

type PMProxy struct {
	mx *ServeMux
	qa *QAdm
	lg *RLog
	gp *proxy
}

func NewPMProxy(qa *QAdm, lg *RLog) (p *PMProxy) {
	p = new(PMProxy)
	p.qa, p.mx, p.lg = qa, NewServeMux(), lg
	p.mx.HandleFunc(logX, p.logXHF)
	p.mx.HandleFunc(groupQuota, p.groupQuotaHF)
	p.mx.HandleFunc(userCons, p.userConsHF)
	return
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
			w.Header().Set(authHd, scrt)
		}
	} else if r.Method == MethodDelete {
		scrt, e = getScrt(r.Header)
		if e == nil {
			e = p.qa.Logout(r.RemoteAddr, scrt)
		}
	} else {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *PMProxy) groupQuotaHF(w ResponseWriter, r *Request) {
	s, e := getScrt(r.Header)
	gr := new(NameVal)
	if e == nil && r.Method == MethodGet {
		gr.Name = r.URL.Query().Get(groupV)
		p.qa.GetQuota(r.RemoteAddr, s, gr)
		e = encode(w, gr)
	} else if e == nil && r.Method == MethodPut {
		e = decode(r.Body, gr)
		if e == nil {
			p.qa.SetQuota(r.RemoteAddr, s, gr)
		}
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *PMProxy) userConsHF(w ResponseWriter, r *Request) {
	s, e := getScrt(r.Header)
	var usr string
	if e == nil && r.Method == MethodGet {
		usr = r.URL.Query().Get(userV)
	} else {
		e = notSuppMeth(r.Method)
	}
	if e == nil {
		nv := new(NameVal)
		nv.Value, e = p.qa.UserCons(r.RemoteAddr, s, usr)
		e = encode(w, nv)
	}
	writeErr(w, e)
}

func (p *PMProxy) ServeHTTP(w ResponseWriter, r *Request) {
	if r.URL.Host == "" {
		p.mx.ServeHTTP(w, r)
	} else {
		p.gp.ServeHTTP(w, r)
	}
}

func getScrt(h Header) (s string, e error) {
	s = h.Get(authHd)
	if s == "" {
		e = fmt.Errorf("Malformed header")
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
	if e != nil {
		w.Write([]byte(e.Error()))
		w.WriteHeader(StatusBadRequest)
	}
}

func notSuppMeth(m string) (e error) {
	e = fmt.Errorf("Not supported method %s", m)
	return
}
