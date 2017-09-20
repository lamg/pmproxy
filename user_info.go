package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
	l "github.com/lamg/ldaputil"
	"strings"
)

// UserDB is an interface for abstracting user databases
type UserDB interface {
	Login(string, string) (*User, *errors.Error)
}

// LDB is an UserDB implementation using Ldap
type LDB struct {
	ld         *l.Ldap
	adminGroup string
	qgPref     string
}

// NewLDB creates a new LDB
// ld: Object with connection to the Active Directory (AD)
// where users are authenticated and that has their
// information.
// admG: The group in the AD which contains the administators
// of this system.
// qgPref: The group prefix of the group in membership that
// defines the users quota group
func NewLDB(ld *l.Ldap, admG, qgPref string) (r *LDB) {
	r = &LDB{ld, admG, qgPref}
	return
}

// Login logs an user with user name u and password p
func (db *LDB) Login(u, p string) (r *User, e *errors.Error) {
	r, e = new(User), db.ld.Authenticate(u, p)
	var m string
	if e == nil {
		r.UserName = u
		r.Name, e = db.ld.FullName(u)
	}
	if e == nil {
		m, e = db.getQuotaGroup(u)
	}
	if e == nil {
		r.QuotaGroup = m
	}
	var fg string
	if e == nil {
		fg, e = db.ld.DNFirstGroup(u)
	}
	if e == nil {
		r.IsAdmin = fg == db.adminGroup
	}
	return
}

// GetQuotaGroup gets the group specified at distinguishedName
// field
// usr: sAMAccountName
func (db *LDB) getQuotaGroup(usr string) (g string,
	e *errors.Error) {
	var m []string
	m, e = db.ld.MembershipCNs(usr)
	if e == nil {
		i, ok := 0, false
		for !ok && i != len(m) {
			ok = strings.HasPrefix(m[i], db.qgPref)
			if !ok {
				i = i + 1
			}
		}
		if ok {
			g = m[i]
		} else {
			e = &errors.Error{
				Code: ErrorMalformedRecord,
				Err:  fmt.Errorf("Couldn't find the quota group for %s", usr),
			}
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

func newdAuth() (d *dAuth) {
	d = &dAuth{make([]*User, 0)}
	return
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
