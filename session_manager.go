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
	// Authenticate authenticates an user given its
	// user name and password, returning the normalized
	// user name and an error
	Authenticate(string, string) (string, error)
}

// SMng handles opened sessions
type SMng struct {
	// ip - user name
	su *sync.Map
	// swapped sessions map ip-message
	swS *sync.Map
	// authenticator for users
	usr Auth
	cr  *JWTCrypt
	adm *UsrMtch
}

// NewSMng creates a new SMng
func NewSMng(usr Auth, cr *JWTCrypt, adm *UsrMtch) (s *SMng) {
	s = &SMng{
		su:  new(sync.Map),
		swS: new(sync.Map),
		usr: usr,
		cr:  cr,
		adm: adm,
	}
	return
}

// loginUser is used by administrator to log an user
func (s *SMng) loginUser(admIP, user, ip string) (e error) {
	if s.adm.Match(admIP) {
		s.login(user, ip)
	}
	return
}

func (s *SMng) login(user, ip string) {
	var prevIP string
	s.su.Range(func(k, v interface{}) (y bool) {
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
		s.swS.Store(prevIP, ClsByMsg(ip))
		s.swS.Store(ip, RcvFrMsg(prevIP))
		// { prevIP and ip prepared for receiving
		//   a notification  }
		s.su.Delete(prevIP)
		// { session in prevIP closed for user }
	}
	s.su.Store(ip, user)
}

// logoutUser is used by administrators to close an user
// session
func (s *SMng) logoutUser(adm, admIP, usr, ip string) (e error) {
	if s.adm.Match(admIP) {
		e = s.logout(usr, ip)
	}
	return
}

func (s *SMng) logout(user, ip string) (e error) {
	u, ok := s.su.Load(ip)
	if ok && u == user {
		m.Delete(ip)
	} else {
		e = NotOpBySMsg(user, ip)
	}
	return
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

func (s *SMng) Match(ip string) (usr, b bool) {
	v, b := s.su.Load(ip)
	if b {
		usr = v.(string)
	}
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
		*s.User = u.(string)
	} else {
		*s.User = ""
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
	} else if r.Method == h.MethodGet {
		e = s.srvSessions(r.Header, ip, w)
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
	if e == nil && r.Method == h.MethodPost {
		e = s.loginUser(ip, ui.User, ui.IP)
	} else if e == nil && r.Method == h.MethodPut {
		e = s.logoutUser(ip, ui.User, ui.IP)
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

func (s *SMng) srvSessions(a h.Header, ip string, w io.Writer) (e error) {
	usr, e := cr.getUser(a)
	if e == nil {
		s.adm.MatchUsr(usr, ip)
	}
	if e == nil {
		mp := make(map[string]string)
		s.su.Range(func(k, v interface{}) (c bool) {
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
