package pmproxy

import (
	ld "github.com/lamg/ldaputil"
)

type userDB struct {
	name   string
	params map[string]interface{}
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

func newADUserDB(params map[string]interface{}) (u *userDB,
	e error) {
	ldap := new(ld.Ldap)
	mpErr := func(key string) (r string, e error) {
		r, ok := params[key]
		if !ok {
			e = fmt.Errorf("Key %s not found", key)
		}
		return
	}
	fe := []func(){
		func() {
			ldap.Addr, e = mpErr(addrK)
		},
		func() {
			ldap.BaseDN, e = mpErr(bdnK)
		},
		func() {
			ldap.Suff, e = mpErr(suffK)
		},
		func() {
			ldap.User, e = mpErr(userK)
		},
		func() {
			ldap.Pass, e = mpErr(passK)
		},
		func() {
			u = &userDB{
				params:   params,
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
	ib := func(i int) (b bool) {
		fe(i)()
		b = e != nil
		return
	}
	bLnSrch(ib, len(fe))
	return
}
