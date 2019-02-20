package pmproxy

import (
	"encoding/json"
)

type sessionIPM struct {
	name     string
	iu       *ipUserS
	authName string
	nameAuth func(string) (auth, bool)
	cr       *crypt
	closeIP  func(string)
}

func (m *sessionIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				m.name = stringE(i, fe)
			},
		},
		{
			authNameK,
			func(i interface{}) {
				m.authName = stringE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (m *sessionIPM) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			open,
			func() {
				c.bs, c.e = m.open(c.Cred, c.RemoteAddr)
			},
		},
		{
			clöse,
			func() {
				c.bs, c.e = m.close(c.Secret, c.RemoteAddr)
			},
		},
		{
			get,
			func() {
				if c.IsAdmin {
					c.bs, c.e = m.get(c.Secret, c.RemoteAddr)
				}
			},
		},
	}
	return
}

func (m *sessionIPM) match(ip string) (ok bool) {
	_, ok = m.iu.get(ip)
	return
}

func (m *sessionIPM) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:     m.name,
		authNameK: m.authName,
	}
	return
}

func (m *sessionIPM) open(c *credentials,
	ip string) (bs []byte, e error) {
	// TODO investigate JWT convention
	// a map of user - opened session date, and a token
	// with user and opened session date should be sufficient
	// for checking the authenticity of a request
	var a auth
	var user string
	fs := []func(){
		func() {
			var ok bool
			a, ok = m.nameAuth(m.authName)
			if !ok {
				e = noKey(m.authName)
			}
		},
		func() {
			user, e = a(c.User, c.Pass)
		},
		func() {
			bs, e = m.cr.encrypt(user)
		},
		func() {
			var oldIP string
			m.iu.mäp.Range(func(k, v interface{}) (cont bool) {
				cont = v.(string) != user
				return
			})
			if oldIP != "" {
				m.iu.mäp.Delete(oldIP)
			}
			m.iu.mäp.Store(ip, user)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (m *sessionIPM) close(secret, ip string) (bs []byte,
	e error) {
	user, e := m.cr.decrypt(secret)
	if e == nil {
		lusr, ok := m.iu.get(ip)
		if ok && lusr == user {
			m.iu.del(ip)
		}
	}
	return
}

func (m *sessionIPM) get(secret, ip string) (bs []byte,
	e error) {
	mp := map[string]string{}
	m.iu.mäp.Range(func(k, v interface{}) (cont bool) {
		mp[k.(string)] = v.(string)
		cont = true
		return
	})
	bs, e = json.Marshal(mp)
	return
}
