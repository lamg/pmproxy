package pmproxy

import (
	"fmt"
)

type IPUser interface {
	User(string) *User
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type SMng struct {
	// ip - *User
	sessions map[string]*User
	udb      UserDB
	crt      *JWTCrypt
}

func (s *SMng) Init(a UserDB, c *JWTCrypt) {
	s.sessions, s.udb, s.crt = make(map[string]*User), a, c
	return
}

func (s *SMng) Login(c *Credentials,
	a string) (t string, e error) {
	var usr *User
	usr, e = s.udb.Login(c.User, c.Pass)
	if e == nil {
		t, e = s.crt.Encrypt(usr)
	}
	if e == nil {
		s.sessions[a] = usr
	}
	return
}

func (s *SMng) Logout(ip, scrt string) (e error) {
	var u *User
	u, e = s.Check(ip, scrt)
	if e == nil {
		delete(s.sessions, u.Name)
	}
	return
}

func (s *SMng) Check(ip, t string) (u *User, e error) {
	u, e = s.crt.Decrypt(t)
	if e == nil {
		var ok bool
		var lu *User
		lu, ok = s.sessions[ip]
		if !(ok && u.Equal(lu)) {
			e = fmt.Errorf("User %s not logged", u.Name)
		}
	}
	return
}

func (s *SMng) User(ip string) (u *User) {
	u, _ = s.sessions[ip]
	return
}
