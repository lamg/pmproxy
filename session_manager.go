package pmproxy

import (
	"fmt"
)

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type SMng struct {
	// user-secret
	sessions map[string]string
	// ip-user
	ipUsr map[string]string
	auth  Authenticator
	crt   Crypt
}

func (s *SMng) Init(a Authenticator, c Crypt) {
	s.sessions, s.ipUsr, s.auth, s.crt =
		make(map[string]string), make(map[string]string), a, c
	return
}

func (s *SMng) Login(c *Credentials,
	a string) (t string, e error) {
	e = s.auth.Authenticate(c.User, c.Pass)
	if e == nil {
		t, e = s.crt.Encrypt(&User{Name: c.User})
	}
	if e == nil {
		s.sessions[c.User], s.ipUsr[a] = t, c.User
	}
	return
}

func (s *SMng) Logout(scrt string) (e error) {
	var u *User
	u, e = s.Check(scrt)
	if e == nil {
		delete(s.sessions, u.Name)
	}
	return
}

func (s *SMng) Check(t string) (u *User, e error) {
	if e == nil {
		u, e = s.crt.Decrypt(t)
	}
	if e == nil {
		var ok bool
		var scrt string
		scrt, ok = s.sessions[u.Name]
		if !ok {
			e = fmt.Errorf("User %s not logged", u.Name)
		} else if t != scrt {
			e = fmt.Errorf("Wrong secret for %s", u.Name)
		}
	}
	return
}

func (s *SMng) UserName(addr string) (n string) {
	n = s.ipUsr[addr]
	return
}
