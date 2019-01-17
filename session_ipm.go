package pmproxy

import (
	"encoding/json"
	"fmt"

	"sync"
)

type sessionIPM struct {
	Name   string `json:"name"`
	UserDB string `json:"userDB"`

	usrDB    func(string) *userDB
	admins   func() []string
	sessions *sync.Map
	crypt    func() *crypt
	grpCache *sync.Map
}

func newSessionIPM(name string, admins func() []string,
	cr *Crypt, udb *userDB) (s *sessionIPM) {
	s = &sessionIPM{
		Name:     name,
		sessions: new(sync.Map),
		Admins:   admins,
		crypt:    cr,
		usrDB:    usrDB,
		grpCache: new(sync.Map),
	}
	return
}

func (s *sessionIPM) manager() (m *manager) {
	m = &manager{
		name: s.Name,
		tỹpe: "sessionIPM",
		cons: idConsR(),
		mtch: func(s string) (ok bool) {
			_, b = s.sessions.Load(ip)
			return
		},
		adm: s.exec,
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK:   s.Name,
				userDBK: s.UserDB.name,
			}
			return
		},
	}
}

func (s *sessionIPM) exec(cmd *AdmCmd) (bs []byte, e error) {
	switch cmd.Cmd {
	case "open":
		bs, e = s.open(cmd.User, cmd.Pass, cmd.RemoteIP)
	case "close":
		bs, e = s.close(cmd.Secret, cmd.RemoteIP)
	case "show":
		if cmd.IsAdmin {
			bs, e = s.show(cmd.Secret, cmd.RemoteIP)
		} else {
			e = NoCmd(cmd.Cmd)
		}
	default:
		e = NoCmd(cmd.Cmd)
	}
	return
}

func (s *sessionIPM) open(usr, pass, ip string) (bs []byte,
	e error) {
	udb, e := s.usrDB(s.UserDB)
	var user string
	if e == nil {
		user, e = udb.authNorm(usr, pass)
	}

	if e == nil {
		bs, e = s.crypt.Encrypt(user)
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

func (s *sessionIPM) close(secr, ip string) (bs []byte,
	e error) {
	var user string
	user, e = s.crypt.Decrypt(secr)
	if e == nil {
		lusr, ok := s.sessions.Load(ip)
		if ok && user == lusr.(string) {
			s.sessions.Delete(ip)
			s.grpCache.Delete(ip)
		}
	}
	return
}

func (s *sessionIPM) show(secret, ip string) (bs []byte,
	e error) {
	var user string
	user, e = checkAdmin(secret, s.crypt, s.Admins)
	if e == nil && user != s.User(ip) {
		e = NoAdmLogged(ip)
	}
	if e == nil {
		mp := make(map[string]string)
		s.sessions.Range(func(k, v interface{}) (ok bool) {
			ok, mp[k.(string)] = true, v.(string)
			return
		})
		bs, e = json.Marshal(&mp)
	}
	return
}

func NoAdmLogged(ip string) (e error) {
	e = fmt.Errorf("No administrator logged at %s", ip)
	return
}

func (s *sessionIPM) user(ip string) (usr string) {
	u, _ := s.sessions.Load(ip)
	usr = u.(string)
	return
}

func (s *sessionIPM) ipGroup(i ip) (gs []string, e error) {
	v, ok := s.grpCache.Load(i)
	if ok {
		gs = v.([]string)
	} else {
		usr := s.user(i)
		if usr != "" {
			gs, e = s.usrDB().grps(usr)
		}
	}
	return
}
