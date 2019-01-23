package pmproxy

import (
	"fmt"
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/cast"
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
	addrK      = "addr"
	bdnK       = "bdn"
	suffK      = "suff"
	userK      = "user"
	passK      = "pass"
	srcK       = "source"
	adSrc      = "ADSrc"
	mapSrc     = "MapSrc"
	paramsK    = "params"
	userPassK  = "userPass"
	userGroupK = "userGroup"
	userDBT    = "userDB"
)

func (u *userDB) fromMap(i interface{}) (e error) {
	m, e := cast.ToStringMapE(i)
	me := func(f func(interface{})) (fk func(string)) {
		fk = mpErr(m, func(d error) { e = d }, f)
		return
	}
	fa := []struct {
		d string
		f func(interface{})
	}{
		{
			nameK,
			func(i interface{}) {
				u.Name, e = cast.ToStringE(i)
			},
		},
		{
			paramsK,
			func(i interface{}) {
				u.Params, e = cast.ToStringMapE(i)
			},
		},
		{
			srcK,
			func(i interface{}) {
				u.SrcType, e = cast.ToStringE(i)
			},
		},
	}
	fe := []func(){
		func() {
			bLnSrch(func(i int) (b bool) {
				me(fa[i].f)(fa[i].k)
				b = e != nil
				return
			},
				len(fa))
		},
		func() {
			if u.SrcType == adSrc {
				e = u.initAD()
			} else if u.SrcType == mapSrc {
				e = u.initMap()
			}
		},
	}
	bLnSrch(ferror(fe, func() bool { return e != nil }), len(fe))
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
	tỹpe = userDBT
	i = map[string]interface{}{
		nameK:   u.Name,
		srcK:    u.SrcType,
		paramsK: u.Params,
	}
	return
}

func (u *userDB) initMap() (e error) {
	me := func(f func(interface{})) (fk func(string)) {
		fk = mpErr(u.Params, func(d error) { e = d }, f)
		return
	}
	fs := []struct {
		k string
		f func(interface{})
	}{
		{
			userPassK,
			func(i interface{}) {
				usrPass, e = cast.ToStringMapStringE(i)
			},
		},
		{
			userGroupK,
			func(i interface{}) {
				usrGrp, e = cast.ToStringMapStringSliceE(i)
			},
		},
	}
	bLnSrch(func(i int) (b bool) {
		me(fs[i].f)(fs[i].k)
		b = e != nil
		return
	},
		len(fs))
	if e == nil {
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
	}
	return
}
