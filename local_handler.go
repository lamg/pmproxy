package pmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	h "net/http"
	"path"

	"github.com/rs/cors"
)

const (
	// ProxyA path to automatic proxy configuration file
	ProxyA = "/proxy.pac"
	// LogX path to login, logout (POST, DELETE)
	LogX = "/api/auth"
	// UserStatus path to get status (GET, PUT)
	// The method PUT currently is used for setting
	// the consumption of a secific user
	UserStatus = "/api/userStatus"
	// CheckUser is the path to get whether an user is logged
	// with the supplied credentials
	CheckUser = "/api/checkUser"
	// UserInfo is the path for getting user information
	UserInfo = "/api/userInfo"
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
	mx.HandleFunc("/", p.proxyA)
	mx.HandleFunc(LogX, p.logXHF)
	mx.HandleFunc(UserStatus, p.userStatusHF)
	mx.HandleFunc(CheckUser, p.checkUserHF)
	mx.HandleFunc(UserInfo, p.userInfoHF)
	p.hn = cors.AllowAll().Handler(mx)
	//FIXME only the web interface should do cross origin
	// requests
	return
}

func (p *LocalHn) proxyA(w h.ResponseWriter, r *h.Request) {
	pth := r.URL.Path[1:]
	if pth == "login" || pth == "login/" {
		pth = ""
	}
	h.ServeFile(w, r, path.Join(p.stPath, pth))
}

func (p *LocalHn) logXHF(w h.ResponseWriter, r *h.Request) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	var e error

	if r.Method == h.MethodPost {
		cr := new(credentials)
		e = Decode(r.Body, cr)
		r.Body.Close()
		var lr *LogRs
		if e == nil {
			lr, e = p.qa.login(cr, addr)
			if e != nil {
				e = fmt.Errorf("Login error: %s", e.Error())
			}
		}
		if e == nil {
			e = Encode(w, lr)
		}
	} else if r.Method == h.MethodDelete {
		s, e := getScrt(r.Header)
		if e == nil {
			e = p.qa.logout(addr, s)
		}
	} else {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

// QtCs is used for storing quota and consumption
type QtCs struct {
	Quota       uint64 `json:"quota"`
	Consumption uint64 `json:"consumption"`
}

// UsrSt represents the consumption that is to be set
// to determined user name, with the credentials for
// doing it.
type UsrSt struct {
	User        *User  `json:"user"`
	UserName    string `json:"userName"`
	Consumption uint64 `json:"consumption"`
}

func (p *LocalHn) userStatusHF(w h.ResponseWriter, r *h.Request) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	var q, c uint64
	s, e := getScrt(r.Header)
	if e == nil && r.Method == h.MethodGet {
		q, e = p.qa.getQuota(addr, s)
		if e == nil {
			c, _ = p.qa.userCons(addr, s)
		}
		if e == nil {
			e = Encode(w, &QtCs{
				Quota:       q,
				Consumption: c,
			})
		}
	} else if e == nil && r.Method == h.MethodPut {
		nv := new(NameVal)
		e = Decode(r.Body, nv)
		r.Body.Close()
		if e == nil {
			e = p.qa.setCons(addr, s, nv)
		}
	} else if e == nil && r.Method == h.MethodPost {
		_, e = p.qa.sm.userInfo(addr, s)
		var bs []byte
		if e == nil {
			bs, e = ioutil.ReadAll(r.Body)
		}
		var c *credentials
		if e == nil {
			c, e = p.qa.sm.crt.checkUser(s)
		}
		var u *User
		if e == nil {
			usr := string(bs)
			u, e = p.qa.sm.udb.UserInfo(c.User, c.Pass, usr)
		}
		var qc *QtCs
		if e == nil {
			qc = new(QtCs)
			qc.Consumption, _ = p.qa.uc.Load(u.UserName)
			qc.Quota, e = p.qa.getUsrQuota(u)
		}
		if e == nil {
			e = Encode(w, qc)
		}
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}

	writeErr(w, e)
}

func (p *LocalHn) checkUserHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	var addr string
	if e == nil {
		if r.Method == h.MethodGet {
			addr, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			e = notSuppMeth(r.Method)
		}
	}
	if e == nil {
		_, e = p.qa.sm.check(addr, s)
	}
	writeErr(w, e)
}

func (p *LocalHn) userInfoHF(w h.ResponseWriter, r *h.Request) {
	s, e := getScrt(r.Header)
	var addr string
	if e == nil {
		if r.Method == h.MethodGet {
			addr, _, _ = net.SplitHostPort(r.RemoteAddr)
		} else {
			e = notSuppMeth(r.Method)
		}
	}
	var u *User
	if e == nil {
		u, e = p.qa.sm.userInfo(addr, s)
	}
	if e == nil {
		e = Encode(w, u)
	}
	writeErr(w, e)
}

func (p *LocalHn) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	p.hn.ServeHTTP(w, r)
}

func getScrt(h h.Header) (s string, e error) {
	s = h.Get(AuthHd)
	if s == "" {
		e = fmt.Errorf("Malformed header")
	}
	return
}

// Decode decodes an io.Reader with a JSON formatted object
func Decode(r io.Reader, v interface{}) (e error) {
	var bs []byte
	bs, e = ioutil.ReadAll(r)
	if e == nil {
		e = json.Unmarshal(bs, v)
	}
	return
}

// Encode encodes an object in JSON notation into w
func Encode(w io.Writer, v interface{}) (e error) {
	cd := json.NewEncoder(w)
	cd.SetIndent("	", "")
	e = cd.Encode(v)
	return
}

func writeErr(w h.ResponseWriter, e error) {
	if e != nil {
		// The order of the following commands matter since
		// httptest.ResponseRecorder ignores parameter sent
		// to WriteHeader if Write was called first
		w.WriteHeader(h.StatusBadRequest)
		w.Write([]byte(e.Error()))
	}
}

func notSuppMeth(m string) (e error) {
	e = fmt.Errorf("Not supported method %s", m)
	return
}
