package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"io"
	"io/ioutil"
	h "net/http"
	"strings"
	"unicode"
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

const (
	// ErrorEncode is the error returned when calling encode
	ErrorEncode = iota
	// ErrorNSMth is the error returned when the method is
	// not supported by a handler
	ErrorNSMth
	// ErrorDecode is the error returned when calling decode
	ErrorDecode
	// ErrorGScrt is the error returned when calling getScrt
	ErrorGScrt
)

// PMProxy is an HTTP server for proxying requests and
// administrating quotas other aspects
type localHn struct {
	mx *h.ServeMux
	qa *QAdm
}

// newLocalHn creates a new localHn
func newLocalHn(qa *QAdm) (p *localHn) {
	p = new(localHn)
	p.qa, p.mx = qa, h.NewServeMux()
	p.mx.HandleFunc(logX, p.logXHF)
	p.mx.HandleFunc(groupQuota, p.groupQuotaHF)
	p.mx.HandleFunc(userCons, p.userConsHF)
	return
}

func (p *localHn) logXHF(w h.ResponseWriter, r *h.Request) {
	addr := trimPort(r.RemoteAddr)
	var e *errors.Error
	var scrt string

	if r.Method == h.MethodPost {
		cr := new(credentials)
		e = decode(r.Body, cr)
		if e == nil {
			scrt, e = p.qa.login(cr, addr)
		}
		if e == nil {
			w.Header().Set(authHd, scrt)
		}
	} else if r.Method == h.MethodDelete {
		scrt, e = getScrt(r.Header)
		if e == nil {
			e = p.qa.logout(addr, scrt)
		}
	} else {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *localHn) groupQuotaHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	gr, addr := new(nameVal), trimPort(r.RemoteAddr)
	if e == nil && r.Method == h.MethodGet {
		gr.Name = r.URL.Query().Get(groupV)
		p.qa.getQuota(addr, s, gr)
		e = encode(w, gr)
	} else if e == nil && r.Method == h.MethodPut {
		e = decode(r.Body, gr)
		if e == nil {
			p.qa.setQuota(addr, s, gr)
		}
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func (p *localHn) userConsHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	var usr string
	if e == nil && r.Method == h.MethodGet {
		usr = r.URL.Query().Get(userV)
	} else {
		e = notSuppMeth(r.Method)
	}
	nv := &nameVal{Name: usr}
	if e == nil {
		addr := trimPort(r.RemoteAddr)
		e = p.qa.userCons(addr, s, nv)
	}
	if e == nil {
		e = encode(w, nv)
	}
	writeErr(w, e)
}

func (p *localHn) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.mx.ServeHTTP(w, r)
}

func getScrt(h h.Header) (s string, e *errors.Error) {
	s = h.Get(authHd)
	if s == "" {
		e = &errors.Error{
			Code: ErrorGScrt,
			Err:  fmt.Errorf("Malformed header"),
		}
	}
	return
}

func decode(r io.Reader, v interface{}) (e *errors.Error) {
	var bs []byte
	var ec error
	bs, ec = ioutil.ReadAll(r)
	if ec == nil {
		ec = json.Unmarshal(bs, v)
	}
	if ec != nil {
		e = &errors.Error{
			Code: ErrorDecode,
			Err:  ec,
		}
	}
	return
}

func encode(w io.Writer, v interface{}) (e *errors.Error) {
	var bs []byte
	var ec error
	bs, ec = json.Marshal(v)
	if ec == nil {
		_, ec = w.Write(bs)
	}
	if ec != nil {
		e = &errors.Error{
			Code: ErrorEncode,
			Err:  ec,
		}
	}
	return
}

func writeErr(w h.ResponseWriter, e *errors.Error) {
	if e != nil {
		// The order of the following commands matter since
		// httptest.ResponseRecorder ignores parameter sent
		// to WriteHeader if Write was called first
		w.WriteHeader(h.StatusBadRequest)
		w.Write([]byte(e.Error()))
	}
}

func notSuppMeth(m string) (e *errors.Error) {
	e = &errors.Error{
		Code: ErrorNSMth,
		Err:  fmt.Errorf("Not supported method %s", m),
	}
	return
}

func trimPort(s string) (r string) {
	q := strings.TrimRightFunc(s,
		func(c rune) (b bool) {
			b = unicode.IsDigit(c)
			return
		})
	r = strings.TrimRight(q, ":")
	return
}
