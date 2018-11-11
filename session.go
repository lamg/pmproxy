package pmproxy

import (
	"encoding/json"
	"fmt"
	"sync"
)

type SessionMng struct {
	sessions *sync.Map
	admins   []string
	crypt    *Crypt
	auth     Authenticator
}

type Authenticator interface {
	AuthAndNorm(string, string) (string, error)
}

func (s *SessionMng) Exec(cmd *AdmCmd) (r string, e error) {
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

func (s *SessionMng) Match(ip string) (b bool) {
	_, b = s.sessions.Load(ip)
	return
}

func NoCmdWithName(cmd string) (e error) {
	e = fmt.Errorf("No command with name %s", cmd)
	return
}

func (s *SessionMng) open(usr, pass, ip string) (r string, e error) {
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

func (s *SessionMng) close(secr, ip string) (r string,
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

func (s *SessionMng) show(secret, ip string) (r string, e error) {
	var user string
	user, e = s.crypt.Decrypt(secret)
	var bs []byte
	if e == nil {
		b := false
		// TODO
		if ok {
			adm := va.(string)
			s.User(ip)
			for i := 0; !b && i != len(s.admins); i++ {
				b = s.admins[i] == user
			}
		}

		if ok && b {
			mp := make(map[string]string)
			s.sessions.Range(func(k, v interface{}) (ok bool) {
				ok, mp[k.(string)] = true, v.(string)
				return
			})
			bs, e = json.Marshal(&mp)
		} else {
			e = NoAdmLogged(ip)
		}
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

func (s *SessionMng) User(ip string) (user string) {
	u, _ := s.sessions.Load(ip)
	user = u.(string)
	return
}
