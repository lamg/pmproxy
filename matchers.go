package pmproxy

import (
	"encoding/json"

	ld "github.com/lamg/ldaputil"
)

// GrpMtch matches user groups
type GrpMtch struct {
	Grp string   `json:"grp"`
	Um  *UsrMtch `json:"um"`
	Ld  *ld.Ldap `json:"ld"`
	// Ug is an alternative to Ld
	Ug map[string][]string `json:"ug"`
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

// MarshalJSON is the json.Marshaler implementation
func (m *GrpMtch) MarshalJSON() (bs []byte, e error) {
	// TODO
	return
}

// UnmarshalJSON is the json.Unmarshaler implementation
func (m *GrpMtch) UnmarshalJSON(bs []byte) (e error) {
	// TODO
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

type usrMtchJ struct {
	Ul []string `json:"ul"`
	Sm string   `json:"sm"`
}

// MarshalJSON is the json.Marshaler implementation
func (m *UsrMtch) MarshalJSON() (bs []byte, e error) {
	j := &usrMtchJ{
		Ul: m.Ul,
		Sm: m.Sm.Name,
	}
	bs, e = json.Marshal(j)
	return
}

// UnmarshalJSON is the json.Unmarshaler implementation
func (m *UsrMtch) UnmarshalJSON(bs []byte) (e error) {
	j := new(usrMtchJ)
	e = json.Unmarshal(bs, j)
	if e == nil {
		m.Ul = j.Ul
		m.Sm = &SMng{
			Name: j.Sm,
		}
	}
	return
}
