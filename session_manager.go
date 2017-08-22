package pmproxy

import (
	"fmt"
)

type SMng struct {
	sessions map[Name]string
	ipUsr    map[IP]Name
	auth     Authenticator
	crt      Crypt
}

func (s *SMng) Init(a Authenticator, c Crypt) {
	s.sessions, s.ipUsr, s.auth, s.crt =
		make(map[Name]string), make(map[IP]Name), a, c
	return
}

func (s *SMng) Login(u Name, a IP,
	p string) (t string, e error) {
	e = s.auth.Authenticate(u, p)
	if e == nil {
		t, e = s.crt.Encrypt(&User{Name: string(u)})
	}
	if e == nil {
		s.sessions[u], s.ipUsr[a] = t, u
	}
	return
}

func (s *SMng) Logout(user Name, pass string) (e error) {
	var ok bool
	_, ok = s.sessions[user]
	if !ok {
		e = fmt.Errorf("User %s not logged", user)
	}
	if e == nil {
		e = s.auth.Authenticate(user, pass)
	}
	if e == nil {
		delete(s.sessions, user)
	}
	return
}

func (s *SMng) Check(t string, user Name) (e error) {
	var ok bool
	var scrt string
	scrt, ok = s.sessions[user]
	if !ok {
		e = fmt.Errorf("User %s not logged", user)
	}
	if e == nil {
		ok = t == scrt
		if !ok {
			e = fmt.Errorf("Wrong secret for %s", user)
		}
	}
	var u *User
	if e == nil {
		u, e = s.crt.Decrypt(t)
	}
	if e == nil && u.Name != string(user) {
		e = fmt.Errorf("Internal error: wrong secret for %s", user)
	}
	return
}

func (s *SMng) UserName(addr IP) (n Name) {
	n = s.ipUsr[addr]
	return
}
