package pmproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	h "net/http"
	"sync"
	"time"
)

// Auth authenticates users
type Auth interface {
	Authenticate(string, string) (string, error)
}

// SMng handles opened sessions
type SMng struct {
	// ip - administrator user
	sa *sync.Map
	// ip - user name
	su *sync.Map
	// swapped sessions map ip-message
	swS *sync.Map
	// authenticator for users
	usr Auth
	// authenticator for administrators
	adm Auth
	// current user
	User string
	cr   *JWTCrypt
}

// NewSMng creates a new SMng
func NewSMng(usr, adm Auth, cr *JWTCrypt) (s *SMng) {
	s = &SMng{
		sa:  new(sync.Map),
		su:  new(sync.Map),
		swS: new(sync.Map),
		usr: usr,
		adm: adm,
		cr:  cr,
	}
	return
}

// loginUser is used by administrator to log an user
func (s *SMng) loginUser(adm, admIP, user, ip string) (e error) {
	e = checkUser(s.sa, adm, admIP)
	if e == nil {
		login(s.su, s.swS, user, ip)
	}
	return
}

func login(m, sw *sync.Map, user, ip string) {
	var prevIP string
	m.Range(func(k, v interface{}) (y bool) {
		usr := v.(string)
		y = usr != user
		if !y {
			prevIP = k.(string)
		}
		return
	})
	// { prevIP is the IP different from ip, which has a
	//   session opened by the same user trying to open
	//   this session. prevIP = "" if that session doesn't
	//   exists }
	if prevIP != "" {
		sw.Store(prevIP, ClsByMsg(ip))
		sw.Store(ip, RcvFrMsg(prevIP))
		// { prevIP and ip prepared for receiving
		//   a notification  }
		m.Delete(prevIP)
		// { session in prevIP closed for user }
	}
	m.Store(ip, user)
}

// ClsByMsg is the closed by message
func ClsByMsg(ip string) (m string) {
	m = fmt.Sprintf("Sesión cerrada por %s", ip)
	return
}

// RcvFrMsg is the recovered from message
func RcvFrMsg(ip string) (m string) {
	m = fmt.Sprintf("Sesión recuperada desde %s", ip)
	return
}

// logoutUser is used by administrators to close an user
// session
func (s *SMng) logoutUser(adm, admIP, usr, ip string) (e error) {
	e = checkUser(s.sa, adm, admIP)
	if e == nil {
		e = logout(s.su, usr, ip)
	}
	return
}

func logout(m *sync.Map, user, ip string) (e error) {
	u, ok := m.Load(ip)
	if ok && u == user {
		m.Delete(ip)
	} else {
		e = errors.New(NotOpBySMsg(user, ip))
	}
	return
}

// NotOpBySMsg is the not opened by session message
func NotOpBySMsg(user, ip string) (e error) {
	e = fmt.Errorf("No hay sesión abierta por %s en %s",
		user, ip)
	return
}

// NotOpInSMsg is the not opened in session message
func NotOpInSMsg(ip string) (e error) {
	e = fmt.Errorf("No hay sesión abierta en %s", ip)
	return
}

// ServeHTTP handles requests to the
// proxy according the status (opened/closed session) of the IP
// which made it
func (s *SMng) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	u, ok := s.su.Load(ip)
	v, sw := s.swS.Load(ip)
	if !ok && !sw {
		// { session is closed and there's no message }
		// use HTML template here
		e = NotOpInSMsg(ip)
	} else if sw {
		msg := v.(string)
		// use HTML template here
		e = fmt.Errorf(msg)
		s.swS.Delete(ip)
		// { message written, if appears,
		//   be the session closed or not
		//	 and deleted for avoiding inconsistencies }
	}
	s.resp = sw || !ok
	if !s.resp {
		s.User = u.(string)
	} else {
		s.User = ""
	}
	return
}

// UsrCrd user credentials
type UsrCrd struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// SrvUserSession is an h.Handler used for opening and
// closing regular users's sessions
func (s *SMng) SrvUserSession(w h.ResponseWriter,
	r *h.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	var e error
	if r.Method == h.MethodPost {
		e = srvLogin(s.su, s.swS, s.cr, s.usr, ip, r.Body, w)
	} else if r.Method == h.MethodDelete {
		e = srvLogout(s.su, s.swS, s.cr, ip, r.Header)
	} else {
		e = NotSuppMeth(r.Method)
	}
	writeErr(w, e)
}

// SrvAdmSession is an h.Handler used for administrative
// tasks
func (s *SMng) SrvAdmSession(w h.ResponseWriter,
	r *h.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	var e error
	if r.Method == h.MethodPost {
		e = srvLogin(s.sa, s.swS, s.cr, s.adm, ip, r.Body, w)
	} else if r.Method == h.MethodDelete {
		e = srvLogout(s.sa, s.swS, s.cr, ip, r.Header)
	} else if r.Method == h.MethodGet {
		// { administrator can get the map of logged users }
		e = srvSessions(s.sa, s.su, s.cr, r.Header, ip, w)
	} else {
		e = NotSuppMeth(r.Method)
	}
	writeErr(w, e)
}

// UsrIP user name - ip pair
type UsrIP struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}

// SrvAdmMngS serves the functionality of closing or opening
// sessions for administrators
func (s *SMng) SrvAdmMngS(w h.ResponseWriter, r *h.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	ui := new(UsrIP)
	var e error
	if r.Body != nil {
		e = Decode(r.Body, ui)
	}
	var adm string
	if e == nil {
		adm, e = s.cr.getUser(r.Header)
	}
	if e == nil && r.Method == h.MethodPost {
		e = s.loginUser(adm, ip, ui.User, ui.IP)
	} else if e == nil && r.Method == h.MethodPut {
		e = s.logoutUser(adm, ip, ui.User, ui.IP)
	} else if e == nil {
		e = NotSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func srvLogin(m, sw *sync.Map, cr *JWTCrypt, a Auth,
	ip string, r io.Reader, w io.Writer) (e error) {
	uc := new(UsrCrd)
	e = Decode(r, uc)
	if e == nil {
		uc.User, e = a.Authenticate(uc.User, uc.Pass)
	}
	var s string
	if e == nil {
		login(m, sw, uc.User, ip)
		s, e = cr.encrypt(uc.User)
	}
	if e == nil {
		w.Write([]byte(s))
	}
	// { session opened ≡ e = nil }
	return
}

func srvLogout(m, sw *sync.Map, cr *JWTCrypt, ip string,
	a h.Header) (e error) {
	var usr string
	usr, e = cr.getUser(a)
	if e == nil {
		e = logout(m, usr, ip)
	}
	// { session closed ≡ e = nil }
	return
}

func srvSessions(n, m *sync.Map, cr *JWTCrypt, a h.Header,
	ip string, w io.Writer) (e error) {
	var usr string
	usr, e = cr.getUser(a)
	if e == nil {
		e = checkUser(n, usr, ip)
	}
	if e == nil {
		mp := make(map[string]string)
		m.Range(func(k, v interface{}) (c bool) {
			c, mp[k.(string)] = true, v.(string)
			return
		})
		e = Encode(w, mp)
	}
	// { session map served ≡ e = nil }
	return
}

func checkUser(m *sync.Map, usr, ip string) (e error) {
	v, ok := m.Load(ip)
	if !ok || v.(string) != usr {
		e = errors.New(NotOpBySMsg(usr, ip))
	}
	return
}
