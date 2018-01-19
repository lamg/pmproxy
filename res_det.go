package pmproxy

import (
	"net"
	h "net/http"
	"time"
)

// Res groups a resource group an a resource individual
type Res struct {
	Cn  *Cond  `json:"cn"`
	Qt  *Quota `json:"qt"`
	InD Idet   `json:"inD"`
	// hacer este tipo representable como JSON
}

type Idet interface {
	Det(*h.Request, time.Time, string) string
}

type UsrDet string

func (d UsrDet) Det(r *h.Request, t time.Time, u string) (s string) {
	s = u
	return
}

type IPDet string

func (d IPDet) Det(r *h.Request, t time.Time, u string) (s string) {
	s, _, _ = net.SplitHostPort(r.RemoteAddr)
	return
}

// ResDet determines a group and an individual
// corresponding to the passed parameters
type ResDet interface {
	Det(*h.Request, time.Time, string) (r *Res, e error)
}

// LdapFlt filters users. Implementation may store in memory
// filtering results for some time, for reducing requests
// to LDAP server.
type LdapFlt interface {
	UserOK(string) (bool, error)
}

// RdMng manages a resource determinator
type RdMng struct {
	rs  []*Res
	LdF LdapFlt
}

// Det is the ResDet implementation
func (d *RdMng) Det(r *h.Request, t time.Time,
	usr string) (s *Res, e error) {
	ec, err := make([]Bool, len(d.rs)), new(err)
	for i, j := range d.rs {
		ec[i] = &evCond{
			c:  j.Cn,
			r:  r,
			t:  t,
			ld: d.LdF,
			e:  err,
		}
	}
	y, i := BoundedLinearSearch(ec)
	e = err.e
	if y {
		s = d.rs[i]
	}
	return
}
