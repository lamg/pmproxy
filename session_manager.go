package pmproxy

import (
	"fmt"
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
	// ip - user name
	su *sync.Map
	// swapped sessions map ip-message
	swS *sync.Map
	au  Auth
}

// NewSMng creates a new SMng
func NewSMng() (s *SMng) {
	s = &SMng{new(sync.Map)}
	return
}

// Login logs in an user
func (s *SMng) Login(user, pass, ip string) (e error) {
	e = s.au.Authenticate(user, pass)
	if e == nil {
		var prevIP string
		s.su.Range(func(k, v interface{}) (y bool) {
			usr := v.(string)
			y = usr != user
			if !y {
				prevIP = k.(string)
			}
		})
		if prevIP != "" {
			s.swS.Store(prevIP,
				fmt.Sprintf("Sesión cerrada por %s", ip))
			s.swS.Store(ip,
				fmt.Sprintf("Sesión recuperada desde %s", prevIP))
			// { prevIP and ip prepared for receiving
			//   a notification  }
			s.su.Delete(prevIP)
			// { logged out from another ip }
		}
		s.su.Store(ip, user)
	}
	return
}

// isOpened tells if there is a session opened from
// the supplied IP. Also returns a message for that IP,
// which may be empty.
func (s *SMng) isOpened(ip string) (y bool, m string) {
	// TODO deal with request matchers
	m, _ = s.swS.Load(ip)
	_, y = s.su.Load(ip)
	return
}

// Proc processes requests
func (s *SMng) Proc(a *Msg, r *h.Request) (m *Msg) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	m = new(Msg)
	y, sm := s.isOpened(ip)
}

func (s *SMng) ServeHTTP(w h.ResponseWriter, r *h.Request) {

	if y && m {
		// write a page to w with m and continue
	} else if y && !m {
		// continue
	} else if !y && m {
		// write a page with m
	} else if !y && !m {
		// write a page with the not logged message
	}
}

// Login is an h.HandlerFunc for log in users
func (s *SMng) Login(w h.ResponseWriter, r *h.Request) {
	if r.Method == h.MethodPost {

	}
}

// Logout is an h.HandlerFunc for log out users
func (s *SMng) Logout(w h.ResponseWriter, r *h.Request) {

}
