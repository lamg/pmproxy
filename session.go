package pmproxy

import (
	"encoding/json"
	"fmt"
	"sync"
)

type SessionMng struct {
	sessions *sync.Map
	admin    IPMatcher
	crypt    Crypt
	auth     Authenticator
}

type Authenticator interface {
	AuthAndNorm(string, string) (string, error)
}

func (s *SessionMng) Exec(cmd *AdmCmd) (r string, e error) {
	switch cmd.Cmd {
	case "open":
		r, e = s.open(cmd.Args)
	case "close":
		r, e = s.close(cmd.Args)
	case "show":
		r, e = s.show(cmd.Args)
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

func (s *SessionMng) open(args []string) (r string, e error) {
	// args[0] = user name, args[1] = password, args[2] = ip
	var user string
	if len(args) == 3 {
		user, e = s.auth.AuthAndNorm(args[0], args[1])
	} else {
		e = MalformedArgs()
	}
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
		s.sessions.Store(args[2], user)
	}
	return
}

func MalformedArgs() (e error) {
	e = fmt.Errorf("Malformed args")
	return
}

func (s *SessionMng) close(args []string) (r string, e error) {
	// args[0] = encrypted user name, args[1] = ip
	var user string
	if len(args) == 2 {
		user, e = s.crypt.Decrypt(args[0])
	} else {
		e = MalformedArgs()
	}
	if e == nil {
		lusr, ok := s.sessions.Load(args[1])
		if ok && user == lusr {
			s.sessions.Delete(args[1])
		}
	}
	return
}

func (s *SessionMng) show(args []string) (r string, e error) {
	var bs []byte
	if len(args) == 1 && s.admin.Match(args[0]) {
		mp := make(map[string]string)
		s.sessions.Range(func(k, v interface{}) (ok bool) {
			ok, mp[k.(string)] = true, v.(string)
			return
		})
		bs, e = json.Marshal(&mp)
	} else {
		e = MalformedArgs()
	}
	if e == nil {
		r = string(bs)
	}
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
