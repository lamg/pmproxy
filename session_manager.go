package pmproxy

import (
	"fmt"
	"github.com/gorilla/mux"
	ld "github.com/lamg/ldaputil"
	"io"
	"net"
	h "net/http"
	"sync"
)

// Auth authenticates users
type Auth struct {
	Ld *ld.Ldap
	Um map[string]string
}

// Authenticate authenticates an user given its
// user name and password, returning the normalized
// user name and an error
func (a *Auth) Authenticate(user, pass string) (usr string, e error) {
	if a.Ld == nil {
		p, ok := a.Um[user]
		ok = ok && p == pass
		if ok {
			usr = user
		} else {
			e = WrongPassErr(user)
		}
	} else {
		usr, e = a.Ld.AuthAndNorm(user, pass)
	}
	return
}

func WrongPassErr(user string) (e error) {
	e = fmt.Errorf("Contraseña incorrecta para %s", user)
	return
}

// SMng handles opened sessions
type SMng struct {
	Name string `json:"name"`
	// ip - user name
	su *sync.Map
	// swapped sessions map ip-message
	swS *sync.Map
	// authenticator for users
	Usr *Auth `json:"auth"`
	cr  *JWTCrypt
	Adm *UsrMtch `json:"adm"`
}

// NewSMng creates a new SMng
func NewSMng(name string, usr *Auth, adm *UsrMtch) (s *SMng) {
	s = &SMng{
		Name: name,
		Usr:  usr,
		Adm:  adm,
	}
	s.su, s.swS, s.cr = new(sync.Map), new(sync.Map), NewJWTCrypt()
	return
}

// loginUser is used by administrator to log an user
func (s *SMng) loginUser(admIP, user, ip string) (e error) {
	if s.Adm.Match(admIP) {
		s.login(user, ip)
	} else {
		e = NotAdmin(admIP)
	}
	return
}

func NotAdmin(ip string) (e error) {
	e = fmt.Errorf("Not logged administrator at %s", ip)
	return
}

func (s *SMng) login(user, ip string) {
	prevIP := make([]string, 0)
	s.su.Range(func(k, v interface{}) (y bool) {
		usr := v.(string)
		if usr == user {
			prevIP = append(prevIP, k.(string))
		}
		y = true
		return
	})
	// { prevIP is the IP different from ip, which has a
	//   session opened by the same user trying to open
	//   this session. prevIP = "" if that session doesn't
	//   exists }
	for _, j := range prevIP {
		s.swS.Store(j, ClsByMsg(ip))
		s.swS.Store(ip, RcvFrMsg(j))
		// { prevIP and ip prepared for receiving
		//   a notification }
		s.su.Delete(j)
	}
	s.su.Store(ip, user)
}

// logoutUser is used by administrators to close an user
// session
func (s *SMng) logoutUser(admIP, usr, ip string) (e error) {
	if s.Adm.Match(admIP) {
		e = s.logout(usr, ip)
	}
	return
}

func (s *SMng) logout(user, ip string) (e error) {
	u, ok := s.su.Load(ip)
	if ok && u == user {
		s.su.Delete(ip)
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

func (s *SMng) Match(ip string) (b bool) {
	_, b = s.su.Load(ip)
	return
}

func (s *SMng) MatchUsr(ip string) (user string, b bool) {
	v, b := s.su.Load(ip)
	if b {
		user = v.(string)
	}
	return
}

// UsrCrd user credentials
type UsrCrd struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (s *SMng) SessionHandler() (p *PrefixHandler) {
	p = &PrefixHandler{
		Prefix: "session_manager",
	}
	rt, path := mux.NewRouter(), "/"+s.Name
	rt.HandleFunc(path, s.SrvUserStatus).Methods(h.MethodGet)
	rt.HandleFunc(path, s.ServeLogin).Methods(h.MethodPost)
	rt.HandleFunc(path, s.ServeLogout).Methods(h.MethodDelete)
	p.Hnd = rt
	return
}

func (s *SMng) AdminHandler() (p *PrefixHandler) {
	p = &PrefixHandler{
		Prefix: "session_admin_manager",
	}
	rt, path := mux.NewRouter(), "/"+s.Name
	rt.HandleFunc(path, s.SrvAdmLoginUsr).Methods(h.MethodPost)
	rt.HandleFunc(path, s.SrvAdmLogoutUsr).Methods(h.MethodPut)
	rt.HandleFunc(path, s.SrvAdmSessions).Methods(h.MethodGet)
	p.Hnd = rt
	return
}

// SrvUserSession is an h.Handler used for opening and
// closing regular users's sessions
func (s *SMng) SrvUserStatus(w h.ResponseWriter,
	r *h.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		v, ok := s.swS.Load(ip)
		if ok {
			msg := v.(string)
			w.Write([]byte(msg))
		}
		// send session status if swapped
	}
	writeErr(w, e)
}

func (s *SMng) ServeLogin(w h.ResponseWriter, r *h.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		e = s.srvLogin(s.Usr, ip, r.Body, w)
	}
	writeErr(w, e)
}

func (s *SMng) ServeLogout(w h.ResponseWriter, r *h.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		e = s.srvLogout(ip, r.Header)
	}
	writeErr(w, e)
}

// UsrIP user name - ip pair
type UsrIP struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}

func (s *SMng) SrvAdmLoginUsr(w h.ResponseWriter, r *h.Request) {
	var e error
	if s.Adm == nil {
		e = NotAdmHandler()
	}
	var ip string
	if e == nil {
		ip, _, e = net.SplitHostPort(r.RemoteAddr)
	}
	ui := new(UsrIP)
	if e == nil {
		e = Decode(r.Body, ui)
	}
	if e == nil {
		e = s.loginUser(ip, ui.User, ui.IP)
	}
	writeErr(w, e)
}

func (s *SMng) SrvAdmLogoutUsr(w h.ResponseWriter, r *h.Request) {
	var e error
	if s.Adm == nil {
		e = NotAdmHandler()
	}
	var ip string
	if e == nil {
		ip, _, e = net.SplitHostPort(r.RemoteAddr)
	}
	ui := new(UsrIP)
	if e == nil {
		e = Decode(r.Body, ui)
	}
	if e == nil {
		e = s.logoutUser(ip, ui.User, ui.IP)
	}
	writeErr(w, e)
}

func (s *SMng) SrvAdmSessions(w h.ResponseWriter, r *h.Request) {
	var e error
	if s.Adm == nil {
		e = NotAdmHandler()
	}
	var ip string
	if e == nil {
		ip, _, e = net.SplitHostPort(r.RemoteAddr)
	}
	if e == nil {
		e = s.srvSessions(r.Header, ip, w)
	}
	writeErr(w, e)
}

func NotAdmHandler() (e error) {
	e = fmt.Errorf("No administrator interface available")
	return
}

func (s *SMng) srvLogin(a *Auth, ip string, r io.Reader,
	w io.Writer) (e error) {
	uc := new(UsrCrd)
	e = Decode(r, uc)
	if e == nil {
		uc.User, e = a.Authenticate(uc.User, uc.Pass)
	}
	var scr string
	if e == nil {
		s.login(uc.User, ip)
		scr, e = s.cr.encrypt(uc.User)
	}
	if e == nil {
		w.Write([]byte(scr))
	}
	// { session opened ≡ e = nil }
	return
}

func (s *SMng) srvLogout(ip string, a h.Header) (e error) {
	var usr string
	usr, e = s.cr.user(a)
	if e == nil {
		e = s.logout(usr, ip)
	}
	// { session closed ≡ e = nil }
	return
}

func (s *SMng) srvSessions(a h.Header, ip string, w io.Writer) (e error) {
	// s.Adm ≠ nil
	var usr string
	usr, e = s.Adm.Sm.cr.user(a)
	if e == nil {
		e = checkUser(s.Adm.Sm.su, usr, ip)
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
		e = NotOpBySMsg(usr, ip)
	}
	return
}
