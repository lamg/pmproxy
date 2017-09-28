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
	// GET
	userStatus = "/userStatus"
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
	p.mx.HandleFunc(userStatus, p.userStatusHF)
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
			w.Write([]byte(scrt))
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

type usrSt struct {
	Quota       uint64 `json:"quota"`
	Consumption uint64 `json:"consumption"`
}

func (p *localHn) userStatusHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	addr := trimPort(r.RemoteAddr)
	if e == nil && r.Method == h.MethodGet {
		var q uint64
		q, e = p.qa.getQuota(addr, s)
		var c uint64
		if e == nil {
			c, e = p.qa.userCons(addr, s)
		}
		if e == nil {
			e = encode(w, &usrSt{Quota: q, Consumption: c})
		}
	} else if e == nil {
		e = notSuppMeth(r.Method)
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
