package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
)

const (
	errorCheck = iota
)

// IPUser is an interface for getting *User associated to
// user's names.
type IPUser interface {
	User(string) *User
}

// credentials is a pair of user and password made for
// being sent by the client, serialized as a JSON object
type credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// SMng handles users's sessions
type SMng struct {
	// ip - *User
	sessions map[string]*User
	udb      UserDB
	crt      *JWTCrypt
}

// Init initializes the SMng instance
func (s *SMng) Init(a UserDB, c *JWTCrypt) {
	s.sessions, s.udb, s.crt = make(map[string]*User), a, c
	return
}

func (s *SMng) login(c *credentials,
	a string) (t string, e *errors.Error) {
	var usr *User
	usr, e = s.udb.Login(c.User, c.Pass)
	if e == nil {
		t, e = s.crt.encrypt(usr)
	}
	if e == nil {
		s.sessions[a] = usr
	}
	return
}

func (s *SMng) logout(ip, scrt string) (e *errors.Error) {
	_, e = s.check(ip, scrt)
	if e == nil {
		delete(s.sessions, ip)
	}
	return
}

func (s *SMng) check(ip, t string) (u *User, e *errors.Error) {
	u, e = s.crt.decrypt(t)
	if e == nil {
		var ok bool
		var lu *User
		lu, ok = s.sessions[ip]
		if !(ok && u.Equal(lu)) {
			e = &errors.Error{
				Code: errorCheck,
				Err:  fmt.Errorf("User %s not logged", u.Name),
			}
		}
	}
	return
}

// User returns the User struct associated to ip
func (s *SMng) User(ip string) (u *User) {
	u, _ = s.sessions[ip]
	return
}
