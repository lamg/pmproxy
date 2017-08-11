package main

import (
	"fmt"
)

type SMng struct {
	sessions map[Name]IP
	auth     Authenticator
}

func NewSMng(a Authenticator) (s *SMng) {
	s = &SMng{make(map[IP]Name), a}
	return
}

func (s *SMng) Login(user Name, addr IP, pass string) (e error) {
	e = s.auth.Authenticate(user, pass)
	if e == nil {
		s.sessions[user] = addr
	}
	return
}

const (
	NotOpenedErr = fmt.Errorf(
		"Usuario %s no tiene su cuenta abierta",
		user)
)

func (s *SMng) Logout(user Name, pass string) (e error) {
	e = s.auth.Authenticate(user, pass)
	var ok bool
	ok = Logged(user)
	if e == nil && ok {
		delete(s.sessions, user)
	} else if e == nil && !ok {
		e = NotOpenedErr
	}
	return
}

func (s *SMng) Logged(user Name, addr IP) (b bool) {
	var r IP
	r, b = s.sessions[user]
	b = b && r == IP
	return
}
