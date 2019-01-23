package pmproxy

import (
	"fmt"
	ld "github.com/lamg/ldaputil"
)

type userDB struct {
	Name    string                 `json: "name"`
	Params  map[string]interface{} `json: "params"`
	SrcType string                 `json: "srcType"`
	grps    userGrp
	auth    authNorm
}

type authNorm func(string, string) (string, error)
type userGrp func(string) ([]string, error)

const (
	addrK   = "addr"
	bdnK    = "bdn"
	suffK   = "suff"
	userK   = "user"
	passK   = "pass"
	srcK    = "source"
	adSrc   = "ADSrc"
	mapSrc  = "MapSrc"
	paramsK = "params"
)

func (u *userDB) fromMap(i interface{}) (e error) {

	return
}

func (u *userDB) initAD() (e error) {
	ldap := new(ld.Ldap)

	me := func(fi func(interface{})) (fk func(string)) {
		fk = mpErr(u.Params, func(d error) { e = d }, fi)
		return
	}
	fe := []struct {
		d *string
		k string
	}{
		{&ldap.Addr, addrK},
		{&ldap.BaseDN, bdnK},
		{&ldap.Suff, suffK},
		{&ldap.User, userK},
		{&ldap.Pass, passK},
	}
	fei := func(n int) (fi func(interface{})) {
		fi = func(i interface{}) {
			if e == nil {
				*fe[n].d, e = cast.ToStringE(i)
			}
		}
		return
	}
	bLnSrch(func(i int) (b bool) {
		me(fei(i))(fe[i].k)
		b = e != nil
		return
	},
		len(fe))
	if e == nil {
		u.authNorm = ldap.AuthAndNorm
		u.grps = func(user string) (gs []string, d error) {
			rec, d := ldap.FullRecordAcc(user)
			if d == nil {
				gs, d = ldap.MembershipCNs(rec)
			}
			return
		}
	}
	return
}

func (u *userDB) toSer() (tỹpe string, i interface{}) {
	tỹpe = "userDB"
	i = u.Params
	i[nameK] = u.Name
	return
}

func (u *userDB) initMap() (e error) {
	mpErr := func(k string) (i interface{}) {
		i, ok := u.Params[k]
		if !ok {
			e = NoKey(k)
		}
	}
	var usrPass map[string]string
	var usrGrp map[string][]string
	var vp, vg interface{}
	fe := []func(){
		func() {
			vp = mpErr("userPass")
		},
		func() {
			vg = mpErr("userGroup")
		},
		func() {
			usrPass, ok = vp.(map[string]string)
			if !ok {
				e = fmt.Errorf("Failed usrPass cast")
			}
		},
		func() {
			usrGrp, ok = vg.(map[string][]string)
			if !ok {
				e = fmt.Errorf("Failed usrGrp cast")
			}
		},
		func() {
			u.grps = func(user string) (gs []string, e error) {
				gs, ok := usrGrp[user]
				if !ok {
					e = NoKey(user)
				}
				return
			}
			u.auth = func(user, pass string) (usr string,
				e error) {
				ps, ok := usrPass[user]
				if !ok || pass != ps {
					e = NoKey(user)
				}
				return
			}
		},
	}
	bLnSrch(ferror(fe, func() bool { return e != nil }),
		len(fe))
	return
}
