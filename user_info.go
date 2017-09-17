package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
	l "github.com/lamg/ldaputil"
)

// UserDB is an interface for abstracting user databases
type UserDB interface {
	Login(string, string) (*User, *errors.Error)
}

// LDB is an UserDB implementation using Ldap
type LDB struct {
	ld          *l.Ldap
	adminGroup  string
	quotaGroups []string
}

// NewLDB creates a new LDB
// ld: Object with connection to the Active Directory (AD)
// where users are authenticated and that has their
// information.
// admG: The group in the AD which contains the administators
// of this system.
// qg: Quota groups, which users allowed to use the proxy
// are member of in the AD.
func NewLDB(ld *l.Ldap, admG string, qg []string) (r *LDB) {
	r = &LDB{ld, admG, qg}
	return
}

// Login logs an user with user name u and password p
func (db *LDB) Login(u, p string) (r *User, e error) {
	r, e = new(User), db.ld.Authenticate(u, p)
	var m []string
	if e == nil {
		r.UserName = u
		r.Name, e = db.ld.FullName(u)
	}
	if e == nil {
		m, e = db.ld.Membership(u)
	}
	if e == nil {
		r.IsAdmin, _ = elementOf(m, db.adminGroup)
		var ok bool
		var i int
		ok, i = hasElementOf(m, db.quotaGroups)
		if ok {
			r.QuotaGroup = db.quotaGroups[i]
		}
	}
	return
}

func elementOf(a []string, s string) (ok bool, i int) {
	ok, i = false, 0
	for !ok && i != len(a) {
		ok, i = a[i] == s, i+1
	}
	return
}

func hasElementOf(a, b []string) (ok bool, i int) {
	ok, i = false, 0
	for !ok && i != len(b) {
		ok, _ = elementOf(a, b[i])
		i = i + 1
	}
	return
}

type dAuth struct {
	us []*User
}

func (d *dAuth) init() {
	d.us = make([]*User, 0)
}

func (d *dAuth) Login(u, p string) (r *User, e *errors.Error) {
	if u == p {
		r = &User{
			Name:       u,
			UserName:   u,
			IsAdmin:    len(u) == 4,
			QuotaGroup: "A",
		}
		d.us = append(d.us, r)
	} else {
		e = &errors.Error{
			Code: l.ErrorAuth,
			Err:  fmt.Errorf("Wrong password for %s", u),
		}
	}
	return
}
