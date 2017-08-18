package pmproxy

import (
	"errors"
)

type SMng struct {
	sessions map[Name]IP
	auth     Authenticator
}

func NewSMng(a Authenticator) (s *SMng) {
	s = &SMng{make(map[Name]IP), a}
	return
}

func (s *SMng) Login(user Name, addr IP, pass string) (e error) {
	e = s.auth.Authenticate(user, pass)
	if e == nil {
		s.sessions[user] = addr
	}
	return
}

var (
	NotOpenedErr error
)

func (s *SMng) Logout(user Name, pass string) (e error) {
	e = s.auth.Authenticate(user, pass)
	var ok bool
	ok = s.Logged(user)
	if e == nil && ok {
		delete(s.sessions, user)
	} else if e == nil && !ok {
		e = NotOpenedErr
	}
	return
}

func (s *SMng) Logged(user Name) (b bool) {
	_, b = s.sessions[user]
	return
}

func init() {
	NotOpenedErr = errors.New("No tiene cuenta abierta")
}
