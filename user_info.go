package pmproxy

import (
	"fmt"
	"strings"

	"github.com/lamg/errors"
	l "github.com/lamg/ldaputil"
)

// UserDB is an interface for abstracting user databases
type UserDB interface {
	Authenticate(string, string) *errors.Error
	UserInfo(string, string, string) (*User, *errors.Error)
}

// LDB is an UserDB implementation using Ldap
type LDB struct {
	ldp        *l.Ldap
	adminNames []string
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
func NewLDB(adAddr, suff, bDN, qgPref string,
	admNs []string) (r *LDB) {
	r = &LDB{
		ldp:        l.NewLdap(adAddr, suff, bDN),
		adminNames: admNs,
		qgPref:     qgPref,
	}
	return
}

// Authenticate authenticates the supplied credentials
func (db *LDB) Authenticate(u, p string) (e *errors.Error) {
	e = db.ldp.Authenticate(u, p)
	return
}

// UserInfo gets the user's information
func (db *LDB) UserInfo(u, p, usr string) (r *User, e *errors.Error) {
	var mp map[string][]string
	mp, e = db.ldp.FullRecord(u, p, usr)
	r = &User{UserName: usr, IsAdmin: false}
	r.Name, e = db.ldp.FullName(mp)
	var m string
	if e == nil {
		m, e = db.getQuotaGroup(mp)
	}
	if e == nil {
		r.QuotaGroup = m
	}
	if e == nil {
		for i := 0; !r.IsAdmin && i != len(db.adminNames); i++ {
			r.IsAdmin = db.adminNames[i] == usr
		}
	}
	return
}

// GetQuotaGroup gets the group specified at distinguishedName
// field
// usr: sAMAccountName
func (db *LDB) getQuotaGroup(mp map[string][]string) (g string,
	e *errors.Error) {
	var m []string
	m, e = db.ldp.MembershipCNs(mp)
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
				Err: fmt.Errorf("Couldn't find the quota group for %s",
					mp[l.SAMAccountName]),
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

// DAuth is an UserDB
type DAuth struct {
	us []*User
}

// NewDAuth …
func NewDAuth() (d *DAuth) {
	d = &DAuth{make([]*User, 0)}
	return
}

// Authenticate authenticates credentials
func (d *DAuth) Authenticate(u, p string) (e *errors.Error) {
	return
}

// UserInfo gets user information
func (d *DAuth) UserInfo(u, p, usr string) (r *User, e *errors.Error) {
	if u == p {
		r = &User{
			Name:       usr,
			UserName:   usr,
			IsAdmin:    len(usr) == 4,
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
