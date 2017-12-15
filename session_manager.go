package pmproxy

import (
	"fmt"
	"io"
	"net"
	h "net/http"
	"sync"
)

// Auth authenticates users
type Auth interface {
	Authenticate(string, string) error
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
	rq  <-chan *ProxHnd
	// sc: stop channel
	sc chan<- bool
	// uc: user name channel
	uc chan<- string
	cr *JWTCrypt
}

// NewSMng creates a new SMng
func NewSMng(usr, adm Auth, rq <-chan *ProxHnd,
	sc chan<- bool, uc chan<- string, cr *JWTCrypt) (s *SMng) {
	s = &SMng{
		sa:  new(sync.Map),
		su:  new(sync.Map),
		swS: new(sync.Map),
		usr: usr,
		adm: adm,
		rq:  rq,
		sc:  sc,
		uc:  uc,
		cr:  cr,
	}
	return
}

// Login opens a session for an user
func (s *SMng) Login(user, pass, ip string) (e error) {
	e = s.usr.Authenticate(user, pass)
	if e == nil {
		login(s.su, s.swS, user, ip)
	}
	return
}

// LoginUser is used by administrator to log an user
func (s *SMng) LoginUser(adm, admIP, user, ip string) (e error) {
	e = checkUser(s.sa, adm, ip)
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
		sw.Store(prevIP,
			fmt.Sprintf("Sesión cerrada por %s", ip))
		sw.Store(ip,
			fmt.Sprintf("Sesión recuperada desde %s", prevIP))
		// { prevIP and ip prepared for receiving
		//   a notification  }
		m.Delete(prevIP)
		// { session in prevIP closed for user }
	}
	m.Store(ip, user)
}

// Logout closes a session
func (s *SMng) Logout(user, ip string) (e error) {
	logout(s.su, user, ip)
	return
}

// LogoutUser is used by administrators to close an user
// session
func (s *SMng) LogoutUser(adm, admIP, usr, ip string) (e error) {
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
		e = fmt.Errorf("User %s not logged in %s", user, ip)
	}
	return
}

// HandleAuth handles requests to the proxy sccording
// the status (opened/closed session) of the IP which
// made it
func (s *SMng) HandleAuth() {
	ph := <-s.rq
	ip, _, _ := net.SplitHostPort(ph.Rq.RemoteAddr)
	u, ok := s.su.Load(ip)
	var stop bool
	if !ok {
		// use HTML template here
		ph.RW.Write(
			[]byte(fmt.Sprintf("No hay sesión abierta en %s", ip)))
		stop = true
	}
	var v interface{}
	v, ok = s.swS.Load(ip)
	if ok {
		msg := v.(string)
		// use HTML template here
		ph.RW.Write([]byte(msg))
		stop = true
	}
	s.sc <- stop
	if !stop {
		s.uc <- u.(string)
	}
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
		e = srvLogin(s.su, s.swS, s.usr, ip, r.Body)
	} else if r.Method == h.MethodDelete {
		e = srvLogout(s.su, s.swS, s.cr, ip, r.Header)
	} else {
		e = notSuppMeth(r.Method)
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
		e = srvLogin(s.sa, s.swS, s.adm, ip, r.Body)
	} else if r.Method == h.MethodDelete {
		e = srvLogout(s.sa, s.swS, s.cr, ip, r.Header)
	} else if r.Method == h.MethodGet {
		// { administrator can get the map of logged users }
		e = srvSessions(s.su, s.cr, r.Header, ip, w)
	} else {
		e = notSuppMeth(r.Method)
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
	e := Decode(r.Body, ui)
	var adm string
	if e == nil {
		adm, e = s.cr.getUser(r.Header)
	}
	if e == nil && r.Method == h.MethodPost {
		e = s.LoginUser(adm, ip, ui.User, ui.IP)
	} else if e == nil && r.Method == h.MethodDelete {
		e = s.LogoutUser(adm, ip, ui.User, ui.IP)
	} else if e == nil {
		e = notSuppMeth(r.Method)
	}
	writeErr(w, e)
}

func srvLogin(m, sw *sync.Map, a Auth, ip string, r io.Reader) (e error) {
	uc := new(UsrCrd)
	e = Decode(r, uc)
	if e == nil {
		e = a.Authenticate(uc.User, uc.Pass)
	}
	if e == nil {
		login(m, sw, uc.Pass, ip)
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

func srvSessions(m *sync.Map, cr *JWTCrypt, a h.Header,
	ip string, w io.Writer) (e error) {
	var usr string
	usr, e = cr.getUser(a)
	if v, ok := m.Load(ip); e == nil && ok &&
		v.(string) == usr {
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

func checkUser(m *sync.Map, u, ip string) (e error) {
	x, ok := m.Load(ip)
	ok = ok && x.(string) == u
	if !ok {
		e = fmt.Errorf("Not logged %s at %s", u, ip)
	}
	return
}
