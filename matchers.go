package pmproxy

import (
	ld "github.com/lamg/ldaputil"
)

// GrpMtch matches user groups
type GrpMtch struct {
	Grp string
	Um  *UsrMtch
	Ld  *ld.Ldap
	// Ug is an alternative to Ld
	Ug map[string][]string
}

// Match gets the groups associated to user logged in
// at ip, and check if it is equal to m.Grp
func (m *GrpMtch) Match(ip string) (b bool) {
	usr, b := m.Um.Sm.MatchUsr(ip)
	var gs []string
	if b {
		if m.Ld != nil {
			mp, e := m.Ld.FullRecordAcc(usr)
			if e == nil {
				gs, e = m.Ld.MembershipCNs(mp)
			}
		} else if m.Ug != nil {
			gs, _ = m.Ug[usr]
		}
		b = gs != nil
	}
	if b {
		i := 0
		for ; i != len(gs) && gs[i] != m.Grp; i++ {
		}
		b = i != len(gs)
	}
	return
}

// UsrMtch matches users
type UsrMtch struct {
	// with Ul empty all users match if logged
	Ul []string `json:"ul"`
	Sm *SMng    `json:"sm"`
}

// Match gets the user logged in at ip checks if is
// in the matching user list
func (m *UsrMtch) Match(ip string) (b bool) {
	var usr string
	usr, b = m.Sm.MatchUsr(ip)
	if b && len(m.Ul) != 0 {
		i := 0
		for ; i != len(m.Ul) && m.Ul[i] != usr; i++ {
		}
		b = i != len(m.Ul)
	}
	return
}
