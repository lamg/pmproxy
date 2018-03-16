package pmproxy

import (
	ld "github.com/lamg/ldaputil"
)

type GrpMtch struct {
	Grp string
	Um  *UsrMtch
	Ld  *ld.Ldap
	// Ug is an alternative to Ld
	Ug map[string][]string
}

func (m *GrpMtch) Match(ip string) (b bool) {
	usr, b := m.Um.Sm.Match(ip)
	if b && m.Ld != nil {
		mp, e := m.Ld.FullRecordAcc(usr)
		var gs []string
		if e == nil {
			gs, e = m.Ld.MembershipCNs(mp)
		}
		if e == nil {
			i := 0
			for ; i != len(gs) && gs[i] != m.Grp; i++ {
			}
			b = i != len(gs)
		}
	}
	return
}

type UsrMtch struct {
	Ul []string
	Sm *SMng
}

func (m *UsrMtch) Match(ip string) (b bool) {
	usr, b := m.Sm.Match(ip)
	if b {
		i := 0
		for ; i != len(m.Ul) && m.Ul[i] != usr; i++ {
		}
		b = i != len(m.Ul)
	}
	return
}
