package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
	"sync"
)

const (
	errorCheck = iota
	// ErrorDictDef is the error code meaning that
	// SMng.sessions has a key with type different from *User
	ErrorDictDef
	// ErrorOverwritten is the error code meaning that
	// the current jwt is no longer corresponding to the
	// user associated with the ip
	ErrorOverwritten
)

var ()

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
	sessions *sync.Map
	udb      UserDB
	crt      *JWTCrypt
}

// NewSMng initializes the SMng instance
func NewSMng(a UserDB, c *JWTCrypt) (s *SMng) {
	s = &SMng{
		sessions: new(sync.Map),
		udb:      a,
		crt:      c,
	}
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
		s.sessions.Store(a, usr)
	}
	return
}

func (s *SMng) logout(ip, scrt string) (e *errors.Error) {
	_, e = s.check(ip, scrt)
	if e == nil {
		s.sessions.Delete(ip)
	}
	return
}

func (s *SMng) check(ip, t string) (u *User, e *errors.Error) {
	u, e = s.crt.decrypt(t)
	var iv interface{}
	if e == nil {
		var ok bool
		iv, ok = s.sessions.Load(ip)
		if !ok {
			e = &errors.Error{
				Code: errorCheck,
				Err:  fmt.Errorf("User %s not logged", u.Name),
			}
		}
	}
	var lu *User
	if e == nil {
		var ok bool
		lu, ok = iv.(*User)
		if !ok {
			e = &errors.Error{
				Code: ErrorDictDef,
				Err: fmt.Errorf(
					"The dictionary values must be of type *User"),
			}
		}
	}
	if e == nil && !u.Equal(lu) {
		e = &errors.Error{
			Code: ErrorOverwritten,
			Err: fmt.Errorf("%s is not logged in %s",
				u.UserName, ip),
		}
	}
	return
}

// User returns the User struct associated to ip
func (s *SMng) User(ip string) (u *User) {
	iv, ok := s.sessions.Load(ip)
	if ok {
		u, _ = iv.(*User)
	}
	return
}
