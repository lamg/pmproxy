package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"github.com/rs/cors"
	"io"
	"io/ioutil"
	"net"
	h "net/http"
)

const (
	// LogX path to login, logout (POST, DELETE)
	LogX = "/api/auth"
	// UserStatus path to get status (GET, PUT)
	// The method PUT currently is used for setting
	// the consumption of a secific user
	UserStatus = "/api/userStatus"
	// AuthHd header key of JWT value
	AuthHd = "authHd"
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
	hn     h.Handler
	qa     *QAdm
	stPath string
}

// NewLocalHn creates a new localHn
// sp: static files directory path
func NewLocalHn(qa *QAdm, sp string) (p *LocalHn) {
	p = &LocalHn{
		qa:     qa,
		stPath: sp,
	}
	mx := h.NewServeMux()
	mx.HandleFunc(LogX, p.logXHF)
	mx.HandleFunc(UserStatus, p.userStatusHF)
	p.hn = cors.AllowAll().Handler(mx) //FIXME take care
	// of allowing all origins
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
			if e != nil {
				e.Err = fmt.Errorf("Login error: %s", e.Error())
			}
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
	} else if e == nil && r.Method == h.MethodPut {
		ust := new(UsrSt)
		e = Decode(r.Body, ust)
		println("ok")
		if e != nil {
			println(e.Error())
		}
		if e == nil {
			e = p.qa.setCons(addr, s, &nameVal{
				Name:  ust.Name,
				Value: ust.Consumption,
			})
		}
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}

	writeErr(w, e)
}

func (p *LocalHn) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.hn.ServeHTTP(w, r)
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
