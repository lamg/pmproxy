package pmproxy

import (
	"fmt"
	"net"
	"sync"
)

// SMng handles opened sessions
type SMng struct {
	// ip - *User
	su *sync.Map
}

// NewSMng creates a new SMng
func NewSMng() (s *SMng) {
	s = &SMng{new(sync.Map)}
	return
}

// usrRC wraps a *reqConn, providing also an user name
type usrRC struct {
	rc  *reqConn
	usr *User
}

func (s *SMng) attachUsr(r *reqConn) (n *usrRC, e error) {
	ip, _, _ := net.SplitHostPort(r.rAddr)
	v, ok := s.su.Load(ip)
	if ok {
		u := v.(*User)
		n = &usrRC{r, u}
	} else {
		e = fmt.Errorf("IP %s hasn't an opened session", ip)
	}
	return
}

// User is the type representing a logged user into the
// system
type User struct {
	UserName   string `json:"userName"`
	Name       string `json:"name"`
	IsAdmin    bool   `json:"isAdmin"`
	QuotaGroup string `json:"quotaGroup"`
}
