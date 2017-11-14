package pmproxy

import (
	"fmt"
	"sync"

	"github.com/lamg/errors"
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

// LogRs is the login result sent as JSON
type LogRs struct {
	Scrt string `json:"scrt"`
}

func (s *SMng) login(c *credentials,
	addr string) (lr *LogRs, e *errors.Error) {
	lr = new(LogRs)
	var u *User
	u, e = s.udb.UserInfo(c.User, c.Pass, c.User)
	if e == nil {
		lr.Scrt, e = s.crt.encrypt(c)
	}
	if e == nil {
		var prvAddr string
		s.sessions.Range(func(key, value interface{}) (x bool) {
			v, ok := value.(*User)
			x = true
			if ok && v.UserName == u.UserName {
				prvAddr, _ = key.(string)
				x = false
			}
			return
		})
		s.sessions.Delete(prvAddr)
		// user session at prvAddr closed
		s.sessions.Store(addr, u)
	}
	return
}

func (s *SMng) logout(ip, t string) (e *errors.Error) {
	_, e = s.check(ip, t)
	if e == nil {
		s.sessions.Delete(ip)
	}
	return
}

func (s *SMng) check(ip, t string) (c *credentials,
	e *errors.Error) {
	c, e = s.crt.checkUser(t)
	if e == nil {
		u := s.User(ip)
		if u == nil || u.UserName != c.User {
			e = &errors.Error{
				Code: 0,
				Err:  fmt.Errorf("User %s not logged", c.User),
			}
		}
	}
	return
}

func (s *SMng) userInfo(ip, t string) (u *User, e *errors.Error) {
	var c *credentials
	c, e = s.crt.checkUser(t)
	var iv interface{}
	if e == nil {
		var ok bool
		iv, ok = s.sessions.Load(ip)
		if !ok {
			e = &errors.Error{
				Code: errorCheck,
				Err:  fmt.Errorf("Not logged from %s", ip),
			}
		}
	}
	if e == nil {
		var ok bool
		u, ok = iv.(*User)
		if !ok {
			e = &errors.Error{
				Code: ErrorDictDef,
				Err: fmt.Errorf(
					"The dictionary values must be of type *User"),
			}
		}
	}
	if e == nil && u.UserName != c.User {
		e = &errors.Error{
			Code: ErrorOverwritten,
			Err: fmt.Errorf("%s is not logged in %s",
				u.UserName, ip),
		}
	}
	return
}

func (s *SMng) exists(t, usr string) (e *errors.Error) {
	var c *credentials
	c, e = s.crt.checkUser(t)
	if e == nil {
		_, e = s.udb.UserInfo(c.User, c.Pass, usr)
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
