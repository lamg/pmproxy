package pmproxy

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"strings"
)

type LdapUPR struct {
	c  *ldap.Conn
	sf string
}

// addr: LDAP server address (IP ":" PortNumber)
// sf: User account suffix
func NewLdapUPR(addr string) (l *LdapUPR, e error) {
	l = new(LdapUPR)
	var c *ldap.Conn
	c, e = NewLdapConn(addr)
	if e == nil {
		l.Init(c)
	}
	return
}

func NewLdapConn(addr string) (c *ldap.Conn, e error) {
	var cfg *tls.Config
	cfg = &tls.Config{InsecureSkipVerify: true}
	c, e = ldap.DialTLS("tcp", addr, cfg)
	return
}

func (l *LdapUPR) Init(c *ldap.Conn) {
	l.c, l.sf = c, "@upr.edu.cu"
}

func (l *LdapUPR) Authenticate(user, pass string) (e error) {
	e = l.c.Bind(string(user)+l.sf, pass)
	return
}

const (
	memberOf = "memberOf"
	grpPref  = "UPR-Internet-"
	baseDN   = "dc=upr,dc=edu,dc=cu"
)

func (l *LdapUPR) GetGroup(user string) (g string, e error) {
	var n *ldap.Entry
	var filter string
	var atts []string
	filter, atts =
		fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))",
			user),
		[]string{memberOf}
	n, e = SearchOne(filter, atts, l.c)
	var mb []string
	if e == nil {
		mb = n.GetAttributeValues(memberOf)
		var i int
		var b bool
		i, b = 0, true
		for b && i != len(mb) {
			i, b = i+1, !strings.HasPrefix(mb[i], grpPref)
		}
		if b {
			g = mb[i]
		} else {
			e = fmt.Errorf("Not found group for %s", user)
		}
	}
	// TODO hacer coincidir los grupos de cuotas en el
	// campo memberOf del AD, con el formato "UPR-Internet-"
	return
}

func SearchOne(f string, ats []string, c *ldap.Conn) (n *ldap.Entry, e error) {
	var ns []*ldap.Entry
	ns, e = SearchFilter(f, ats, c)
	if e == nil {
		if len(ns) == 1 {
			n = ns[0]
		} else {
			e = fmt.Errorf("Result length = %d", len(ns))
		}
	}
	return
}

func SearchFilter(f string, ats []string, c *ldap.Conn) (n []*ldap.Entry, e error) {
	var (
		scope                = ldap.ScopeWholeSubtree
		deref                = ldap.NeverDerefAliases
		sizel                = 0
		timel                = 0
		tpeol                = false //TypesOnly
		conts []ldap.Control = nil   //[]Control
		s     *ldap.SearchRequest
		r     *ldap.SearchResult
	)
	s = ldap.NewSearchRequest(baseDN, scope, deref,
		sizel, timel, tpeol, f, ats, conts)
	r, e = c.Search(s)
	if e == nil && len(r.Entries) == 0 {
		e = fmt.Errorf("Failed search of %s", f)
	} else if e == nil {
		n = r.Entries
	}
	return
}

type dAuth struct {
}

func (d *dAuth) Authenticate(user, pass string) (e error) {
	if user != pass {
		e = fmt.Errorf("Wrong password for %s", user)
	}
	return
}

func (d *dAuth) GetGroup(u string) (g string, e error) {
	return
}
