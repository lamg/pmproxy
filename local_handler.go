package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"io"
	"io/ioutil"
	"net"
	h "net/http"
)

const (
	// RootP is the root path
	RootP = "/"
	// StatusP is the status page path
	StatusP = "/status"
	// PublicP public directory path
	PublicP = "/public/"
	// LogX path to login, logout (POST, DELETE)
	LogX = "/api/auth"
	// UserStatus path to get status (GET)
	UserStatus = "/api/userStatus"
	// GET, POST
	accExcp = "/api/accessExceptions"
	// AuthHd header key of JWT value
	AuthHd   = "authHd"
	userV    = "user"
	groupV   = "group"
	loginPg  = "login.html"
	statusPg = "status.html"
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

// LocalHn is an HTTP server for proxying requests and
// administrating quotas other aspects
type LocalHn struct {
	mx     *h.ServeMux
	qa     *QAdm
	stPath string
}

// NewLocalHn creates a new localHn
// sp: static files directory path
func NewLocalHn(qa *QAdm, sp string) (p *LocalHn) {
	p = &LocalHn{
		qa:     qa,
		mx:     h.NewServeMux(),
		stPath: sp,
	}
	p.mx.HandleFunc(LogX, p.logXHF)
	p.mx.HandleFunc(UserStatus, p.userStatusHF)
	p.mx.Handle(RootP, h.FileServer(h.Dir(sp)))
	return
}

func (p *LocalHn) logXHF(w h.ResponseWriter, r *h.Request) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	var e *errors.Error
	var scrt string

	if r.Method == h.MethodPost {
		cr := new(credentials)
		e = Decode(r.Body, cr)
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

// UsrSt is used for storing user information
type UsrSt struct {
	UserName    string `json:"userName"`
	Name        string `json:"name"`
	IsAdmin     bool   `json:"isAdmin"`
	Quota       uint64 `json:"quota"`
	Consumption uint64 `json:"consumption"`
}

func (p *LocalHn) userStatusHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	var q, c uint64
	var u *User
	if e == nil && r.Method == h.MethodGet {
		q, _ = p.qa.getQuota(addr, s)
		c, _ = p.qa.userCons(addr, s)
		u, e = p.qa.sm.check(addr, s)
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}
	if e == nil {
		// TODO probably not the best having a type
		// *User being encrypted with excessive information
		e = Encode(w, &UsrSt{
			UserName:    u.UserName,
			Name:        u.Name,
			IsAdmin:     u.IsAdmin,
			Quota:       q,
			Consumption: c,
		})
	}
	writeErr(w, e)
}

func (p *LocalHn) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.mx.ServeHTTP(w, r)
}

func getScrt(h h.Header) (s string, e *errors.Error) {
	s = h.Get(AuthHd)
	if s == "" {
		e = &errors.Error{
			Code: ErrorGScrt,
			Err:  fmt.Errorf("Malformed header"),
		}
	}
	return
}

// Decode decodes an io.Reader with a JSON formatted object
func Decode(r io.Reader, v interface{}) (e *errors.Error) {
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

// Encode encodes an object in JSON notation into w
func Encode(w io.Writer, v interface{}) (e *errors.Error) {
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
