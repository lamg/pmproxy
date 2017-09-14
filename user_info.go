package pmproxy

import (
	"fmt"
	. "github.com/lamg/ldaputil"
)

type UserDB interface {
	Login(string, string) (*User, error)
}

// UserDB implementation using Ldap
type LDB struct {
	l           *Ldap
	adminGroup  string
	quotaGroups []string
}

// l: Object with connection to the Active Directory (AD)
// where users are authenticated and that has their
// information.
// admG: The group in the AD which contains the administators
// of this system.
// qg: Quota groups, which users allowed to use the proxy
// are member of in the AD.
func NewLDB(l *Ldap, admG string, qg []string) (r *LDB) {
	r = &LDB{l, admG, qg}
	return
}

func (l *LDB) Login(u, p string) (r *User, e error) {
	r, e = new(User), l.l.Authenticate(u, p)
	var m []string
	if e == nil {
		r.UserName = u
		r.Name, e = l.l.FullName(u)
	}
	if e == nil {
		m, e = l.l.Membership(u)
	}
	if e == nil {
		r.IsAdmin, _ = ElementOf(m, l.adminGroup)
		var ok bool
		var i int
		ok, i = HasElementOf(m, l.quotaGroups)
		if ok {
			r.QuotaGroup = l.quotaGroups[i]
		}
	}
	return
}

func ElementOf(a []string, s string) (ok bool, i int) {
	ok, i = false, 0
	for !ok && i != len(a) {
		ok, i = a[i] == s, i+1
	}
	return
}

func HasElementOf(a, b []string) (ok bool, i int) {
	ok, i = false, 0
	for !ok && i != len(b) {
		ok, _ = ElementOf(a, b[i])
		i = i + 1
	}
	return
}

type dAuth struct {
	us []*User
}

func (d *dAuth) Init() {
	d.us = make([]*User, 0)
}

func (d *dAuth) Login(u, p string) (r *User, e error) {
	if u == p {
		r = &User{
			Name:       u,
			UserName:   u,
			IsAdmin:    len(u) == 4,
			QuotaGroup: "A",
		}
		d.us = append(d.us, r)
	} else {
		e = fmt.Errorf("Wrong password for %s", u)
	}
	return
}
