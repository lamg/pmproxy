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
	u, usr = myLower(u), myLower(usr)
	mp, e = db.ldp.FullRecord(u, p, usr)
	if e == nil {
		r = &User{UserName: usr, IsAdmin: false}
		r.Name, e = db.ldp.FullName(mp)
	}
	var m []string
	if e == nil {
		m, e = db.getQuotaGroups(mp)
	}
	if e == nil {
		r.QuotaGroups = m
		r.IsAdmin, _ = elementOf(db.adminNames, usr)
	}
	return
}

// GetQuotaGroup gets the group specified at distinguishedName
// field
// usr: sAMAccountName
func (db *LDB) getQuotaGroups(mp map[string][]string) (g []string,
	e *errors.Error) {
	var m []string
	m, e = db.ldp.MembershipCNs(mp)
	if e == nil {
		g = make([]string, 0, len(m))
		for _, j := range m {
			if strings.HasPrefix(j, db.qgPref) {
				g = append(g, j)
			}
		}
		if len(g) == 0 {
			e = &errors.Error{
				Code: ErrorMalformedRecord,
				Err: fmt.Errorf("Couldn't find quota groups in %s",
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
	us map[string]*User
}

// Authenticate authenticates credentials
func (d *DAuth) Authenticate(u, p string) (e *errors.Error) {
	return
}

// UserInfo gets user information
func (d *DAuth) UserInfo(u, p, usr string) (r *User, e *errors.Error) {
	if u == p {
		var ok bool
		r, ok = d.us[usr]
		if !ok {
			e = &errors.Error{
				Code: l.ErrorAuth,
				Err:  fmt.Errorf("User %s doesn't exists", usr),
			}
		}
	} else {
		e = &errors.Error{
			Code: l.ErrorAuth,
			Err:  fmt.Errorf("Wrong password for %s", u),
		}
	}
	return
}
