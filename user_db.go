package pmproxy

import (
	ld "github.com/lamg/ldaputil"
)

type userDB struct {
	Name   string                 `json: "name"`
	Params map[string]interface{} `json: "params"`
	grps   userGrp
	auth   authNorm
}

type authNorm func(string, string) (string, error)
type userGrp func(string) ([]string, error)

const (
	addrK = "addr"
	bdnK  = "bdn"
	suffK = "suff"
	userK = "user"
	passK = "pass"
)

func newADUserDB(name string,
	params map[string]interface{}) (u *userDB, e error) {
	ldap := new(ld.Ldap)
	mpErr := func(key string) (r string) {
		r, ok := params[key]
		if !ok {
			e = NoKey(key)
		}
		return
	}
	fe := []func(){
		func() {
			ldap.Addr = mpErr(addrK)
		},
		func() {
			ldap.BaseDN = mpErr(bdnK)
		},
		func() {
			ldap.Suff = mpErr(suffK)
		},
		func() {
			ldap.User = mpErr(userK)
		},
		func() {
			ldap.Pass = mpErr(passK)
		},
		func() {
			u = &userDB{
				Pame:     name,
				Params:   params,
				authNorm: ldap.AuthAndNorm,
				grps: func(user string) (gs []string, d error) {
					rec, d := ldap.FullRecordAcc(user)
					if d == nil {
						gs, d = ldap.MembershipCNs(rec)
					}
					return
				},
			}
		},
	}
	bLnSrch(ferror(fe, func() bool { return e != nil }), len(fe))
	return
}

func (u *userDB) toSer() (tỹpe string, i interface{}) {
	tỹpe = "userDB"
	i = u.Params
	i[nameK] = u.Name
	return
}
