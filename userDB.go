package pmproxy

import (
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/cast"
)

type auth func(string, string) (string, error)
type userGroup func(string) ([]string, error)
type userName func(string) (string, error)

type userDB struct {
	name    string
	adOrMap bool
	ath     auth
	grp     userGroup
	unm     userName
}

func (d *userDB) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				d.name = stringE(i, fe)
			},
		},
		{
			adOrMapK,
			func(i interface{}) {
				d.adOrMap = boolE(i, fe)
				if d.adOrMap {
					fe(d.fromMapAD(i))
				} else {
					fe(d.fromMapMap(i))
				}
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

type keyVal struct {
	k, v string
}

func (d *userDB) fromMapAD(i interface{}) (e error) {
	addr, suff, bdn, user, pass :=
		keyVal{k: addrK}, keyVal{k: suffK}, keyVal{k: bdnK},
		keyVal{k: userK}, keyVal{k: passK}
	ks := []keyVal{addr, suff, bdn, user, pass}
	mp, e := cast.ToStringMapE(i)
	ok, _ := trueForall(
		func(i int) (b bool) {
			ks[i].v, e = cast.ToStringE(mp[ks[i].k])
			b = e == nil
			return
		},
		len(ks),
	)
	if ok {
		ldap := ld.NewLdapWithAcc(addr.v, suff.v, bdn.v,
			user.v, pass.v)
		d.ath = ldap.AuthAndNorm
		d.grp = func(user string) (gs []string, e error) {
			mp, e := ldap.FullRecordAcc(user)
			if e == nil {
				gs, e = ldap.MembershipCNs(mp)
			}
			return
		}
		d.unm = func(user string) (name string, e error) {
			mp, e := ldap.FullRecordAcc(user)
			if e == nil {
				name, e = ldap.FullName(mp)
			}
			return
		}
	}
	return
}

func (d *userDB) fromMapMap(i interface{}) (e error) {
	var mp map[string]interface{}
	var upm map[string]string
	var gm map[string][]string
	fs := []func(){
		func() { mp, e = cast.ToStringMapE(i) },
		func() { upm, e = cast.ToStringMapStringE(mp[userPassK]) },
		func() {
			gm, e = cast.ToStringMapStringSliceE(mp[userGroupsK])
		},
	}
	ok := trueFF(fs, func() bool { return e == nil })
	if ok {
		d.ath = func(user, pass string) (nuser string, e error) {
			nuser = user
			p, ok := upm[user]
			if !ok {
				e = noKey(user)
			} else if p != pass {
				e = incorrectPassword()
			}
			return
		}
		d.grp = func(user string) (gs []string, e error) {
			gs, ok := gm[user]
			if !ok {
				e = noKey(user)
			}
			return
		}
		d.unm = func(user string) (name string, e error) {
			name = user
			return
		}
	}
	return
}

func (d *userDB) toMap() (i interface{}) {
	return
}

func (d *userDB) managerKF() (kf []kFunc) {
	return
}
