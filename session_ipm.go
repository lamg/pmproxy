package pmproxy

import (
	"encoding/json"
	"fmt"
	"sync"
)

type sessionIPM struct {
	Name   string `json:"name"`
	UserDB string `json:"userDB"`

	authNormN func(string) authNorm
	usrGroupN func(string) userGrp
	admins    func() []string
	sessions  *sync.Map
	crypt     func() *crypt
	grpCache  *sync.Map
}

const (
	userDBK = "userDB"
)

func (s *sessionIPM) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:   s.Name,
		userDBK: s.UserDB,
	}
	tỹpe = sessionIPMT
	return
}

func (s *sessionIPM) fromMap(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				s.Name = stringE(i, fe)
			},
		},
		{
			userDBK,
			func(i interface{}) {
				s.UserDB = stringE(i, fe)
			},
		},
	}
	return
}

func (s *sessionIPM) match(ip string) (ok bool) {
	_, ok = s.sessions.Load(ip)
	return
}

const (
	sessionIPMT = "sessionIPM"
)

func (s *sessionIPM) admin(cmd *AdmCmd, fb fbs,
	fe ferr) (kf []kFunc) {
	kf = []kFunc{
		{
			open,
			func() {
				bs, e := s.open(cmd.User, cmd.Pass, cmd.RemoteIP)
				fb(bs)
				fe(e)
			},
		},
		{
			clöse,
			func() {
				bs, e := s.close(cmd.Secret, cmd.RemoteIP)
				fb(bs)
				fe(e)
			},
		},
		{
			show,
			func() {
				if cmd.IsAdmin {
					bs, e := s.show(cmd.Secret, cmd.RemoteIP)
					fb(bs)
					fe(e)
				}
			},
		},
	}
	return
}

func (s *sessionIPM) open(usr, pass, ip string) (bs []byte,
	e error) {
	var auth authNorm
	var user string
	fe := []func(){
		func() {
			auth = s.authNormN(s.UserDB)
			if auth == nil {
				e = NoKey(s.UserDB)
			}
		},
		func() {
			user, e = auth(usr, pass)
		},
		func() {
			bs, e = s.crypt().Encrypt(user)
		},
		func() {
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
		},
	}
	bLnSrch(
		ferror(fe, func() bool { return e != nil }),
		len(fe),
	)
	return
}

func MalformedArgs() (e error) {
	e = fmt.Errorf("Malformed args")
	return
}

func (s *sessionIPM) close(secr, ip string) (bs []byte,
	e error) {
	var user string
	user, e = s.crypt().Decrypt(secr)
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
	mp := make(map[string]string)
	s.sessions.Range(func(k, v interface{}) (ok bool) {
		ok, mp[k.(string)] = true, v.(string)
		return
	})
	bs, e = json.Marshal(&mp)
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

func (s *sessionIPM) ipGroup(ip string) (gs []string,
	e error) {
	v, ok := s.grpCache.Load(ip)
	if ok {
		gs = v.([]string)
	} else {
		usr := s.user(ip)
		if usr != "" {
			grp := s.usrGroupN(s.UserDB)
			if grp != nil {
				gs, e = grp(usr)
			} else {
				e = NoKey(s.UserDB)
			}
		}
	}
	return
}

func (s *sessionIPM) ipInfo() (i *ipUserInf) {
	i = &ipUserInf{
		ipg: s.ipGroup,
		ipu: s.user,
	}
	return
}
