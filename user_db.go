package pmproxy

import (
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

func (u *userDB) fromMap(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				u.Name = stringE(i, fe)
			},
		},
		{
			paramsK,
			func(i interface{}) {
				u.Params = stringMapE(i, fe)
			},
		},
		{
			srcK,
			func(i interface{}) {
				u.SrcType = stringE(i, fe)
			},
		},
	}
	// TODO check alternative initializations using an
	// intermediate ferr
	kf = append(kf, u.fromMapKFLd(fe)...)
	kf = append(kf, u.fromMapKFMp(fe)...)
	return
}

func (u *userDB) errFunc(e error) (d error) {
	var ers []string
	if u.SrcType == adSrc {
		ers = []string{userPassK, userGroupK}
	} else if u.SrcType == mapSrc {
		ers = []string{addrK, bdnK, suffK, userK, passK}
	}
	ib := func(i int) (b bool) {
		b = e == NoKey(ers[i])
		return
	}
	ok, _ := bLnSrch(ib, len(ers))
	if ok {
		d = nil
	} else {
		d = e
	}
	// for each u.SrcType the keys valid for the other
	// aren't found in the map, therefore that shouldn't
	// count as an error
	return
}

func (u *userDB) fromMapKFLd(fe ferr) (kf []kFuncI) {
	ldap := new(ld.Ldap)
	ss := []struct {
		s string
		f func(string)
	}{
		{addrK, func(s string) { ldap.Addr = s }},
		{bdnK, func(s string) { ldap.BaseDN = s }},
		{suffK, func(s string) { ldap.Suff = s }},
		{userK, func(s string) { ldap.User = s }},
		{passK, func(s string) { ldap.Pass = s }},
	}
	kf = make([]kFuncI, len(ss))
	inf := func(i int) {
		// putting this check here is the solution I found
		// for optional parameters in map
		kf[i] = kFuncI{
			ss[i].s,
			func(v interface{}) {
				ss[i].f(stringE(v, fe))
			},
		}
	}
	forall(inf, len(kf))
	kf = append(kf, kFuncI{
		passK,
		func(i interface{}) {

			u.auth = ldap.AuthAndNorm
			u.grps = func(user string) (gs []string, d error) {
				rec, d := ldap.FullRecordAcc(user)
				if d == nil {
					gs, d = ldap.MembershipCNs(rec)
				}
				return
			}
		},
	})
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

func (u *userDB) fromMapKFMp(fe ferr) (kf []kFuncI) {
	var userPass map[string]string
	var userGroup map[string][]string
	kf = []kFuncI{
		{
			userPassK,
			func(i interface{}) {
				userPass = stringMapString(i, fe)
			},
		},
		{
			userGroupK,
			func(i interface{}) {
				userGroup = stringMapStringSlice(i, fe)
			},
		},
		{
			userGroupK,
			func(i interface{}) {
				u.grps = func(user string) (gs []string, e error) {
					gs, ok := userGroup[user]
					if !ok {
						e = NoKey(user)
					}
					return
				}
				u.auth = func(user, pass string) (usr string,
					e error) {
					ps, ok := userPass[user]
					if !ok || pass != ps {
						e = NoKey(user)
					}
					return
				}
			},
		},
	}
	return
}
