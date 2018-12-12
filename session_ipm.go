package pmproxy

import (
	"encoding/json"
	"fmt"

	"sync"
)

type sessionIPM struct {
	NameF  string   `json:"name"   toml:"name"`
	Admins []string `json:"admins" toml:"admins"`

	sessions *sync.Map
	crypt    *Crypt
	auth     Authenticator
}

type Authenticator interface {
	AuthAndNorm(string, string) (string, error)
}

func newSessionIPM(name string, admins []string, cr *Crypt,
	auth Authenticator) (s *sessionIPM) {
	s = &sessionIPM{
		NameF:    name,
		sessions: new(sync.Map),
		Admins:   admins,
		crypt:    cr,
		auth:     auth,
	}
	return
}

func (s *sessionIPM) Name() (r string) {
	r = s.NameF
	return
}

func (s *sessionIPM) Exec(cmd *AdmCmd) (r string, e error) {
	switch cmd.Cmd {
	case "open":
		r, e = s.open(cmd.User, cmd.Pass, cmd.RemoteIP)
	case "close":
		r, e = s.close(cmd.Secret, cmd.RemoteIP)
	case "show":
		r, e = s.show(cmd.Secret, cmd.RemoteIP)
	default:
		e = NoCmdWithName(cmd.Cmd)
	}
	return
}

func (s *sessionIPM) Match(ip string) (b bool) {
	_, b = s.sessions.Load(ip)
	return
}

func NoCmdWithName(cmd string) (e error) {
	e = fmt.Errorf("No command with name %s", cmd)
	return
}

func (s *sessionIPM) open(usr, pass, ip string) (r string, e error) {
	var user string
	user, e = s.auth.AuthAndNorm(usr, pass)
	if e == nil {
		r, e = s.crypt.Encrypt(user)
	}
	if e == nil {
		// close session opened by same user
		var oldIP string
		s.sessions.Range(func(k, v interface{}) (ok bool) {
			ok = v.(string) != user
			if !ok {
				oldIP = k.(string)
			}
			return
		})
		if oldIP != "" {
			s.sessions.Delete(oldIP)
		}
		// add to dictionary
		s.sessions.Store(ip, user)
	}
	return
}

func MalformedArgs() (e error) {
	e = fmt.Errorf("Malformed args")
	return
}

func (s *sessionIPM) close(secr, ip string) (r string,
	e error) {
	var user string
	user, e = s.crypt.Decrypt(secr)
	if e == nil {
		lusr, ok := s.sessions.Load(ip)
		if ok && user == lusr.(string) {
			s.sessions.Delete(ip)
		}
	}
	return
}

func (s *sessionIPM) show(secret, ip string) (r string, e error) {
	var user string
	user, e = checkAdmin(secret, s.crypt, s.Admins)
	if e == nil && user != s.User(ip) {
		e = NoAdmLogged(ip)
	}
	var bs []byte
	if e == nil {
		mp := make(map[string]string)
		s.sessions.Range(func(k, v interface{}) (ok bool) {
			ok, mp[k.(string)] = true, v.(string)
			return
		})
		bs, e = json.Marshal(&mp)
	}
	if e == nil {
		r = string(bs)
	}
	return
}

func NoAdmLogged(ip string) (e error) {
	e = fmt.Errorf("No administrator logged at %s", ip)
	return
}

type IPUser interface {
	User(string) string
}

func (s *sessionIPM) User(ip string) (user string) {
	u, _ := s.sessions.Load(ip)
	user = u.(string)
	return
}
