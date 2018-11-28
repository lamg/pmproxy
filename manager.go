package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/clock"
	"sync"
)

type manager struct {
	clock  clock.Clock
	crypt  *Crypt
	adcf   *ADConf
	admins []string
	rspec  *simpleRSpec
	mngs   map[string]*Mng
}

// Mng is the type for storing the types that cannot be fully
// represented in a Rule as JSON
type Mng struct {
	Admin
	// IPMatcher = nil ≢ Cr = nil
	IPM IPMatcher
	Cr  ConsR
}

func (m *Mng) MarshalJSON() (bs []byte, e error) {
	if m.IPM != nil {
		bs, e = json.Marshal(m.IPM)
	} else if m.Cr != nil {
		bs, e = json.Marshal(m.Cr)
	}
	return
}

type ADConf struct {
	user string `json:"user"`
	pass string `json:"pass"`
	addr string `json:"addr"`
	bdn  string `json:"bdn"`
	suff string `json:"suff"`
}

func (s *manager) Exec(cmd *AdmCmd) (r string, e error) {
	adm, ok := s.mngs[cmd.Manager]
	if ok {
		r, e = adm.Exec(cmd)
	} else if cmd.Manager == "" {
		r, e = s.admin(cmd)
	} else if cmd.Manager == "rules" {
		r, e = s.manageRules(cmd)
	} else {
		e = NoMngWithName(cmd.Manager)
	}
	return
}

func (s *manager) manageRules(cmd *AdmCmd) (r string, e error) {
	if cmd.Cmd == "add" {
		e = s.addRule(cmd.Pos, cmd.Rule)
	} else if cmd.Cmd == "del" {
		e = s.rspec.remove(cmd.Pos)
	} else if cmd.Cmd == "show" {
		r, e = s.rspec.show()
	} else {
		e = NoCmd(cmd.Cmd)
	}
	return
}

func (s *manager) addRule(pos []int, jr *JRule) (e error) {
	var rule *Rule
	if jr != nil {
		rule = &Rule{
			Unit: jr.Unit,
			span: jr.Span,
			Spec: &Spec{
				Iface:    jr.Spec.Iface,
				ProxyURL: jr.Spec.ProxyURL,
				Cr:       make([]ConsR, 0),
			},
		}
		if jr.IPM != "" {
			mng, ok := s.mngs[jr.IPM]
			if ok && mng.IPM != nil {
				rule.IPM = mng.IPM
			} else if !ok {
				e = NoMngWithName(jr.IPM)
			} else if mng.IPM == nil {
				e = NoMngWithType(jr.IPM, "IPMatcher")
			}
		}
		for i := 0; e == nil && i != len(jr.Spec.ConsR); i++ {
			mng, ok := s.mngs[jr.Spec.ConsR[i]]
			if ok && mng.Cr != nil {
				rule.Spec.Cr = append(rule.Spec.Cr, mng.Cr)
			} else if !ok {
				e = NoMngWithName(jr.Spec.ConsR[i])
			} else if mng.Cr == nil {
				e = NoMngWithType(jr.Spec.ConsR[i], "ConsR")
			}
		}
	} else {
		e = InvalidArgs("add")
	}
	// converted from *JRule to *Rule
	if e == nil {
		e = s.rspec.add(pos, rule)
	}
	return
}

func NoCmd(name string) (e error) {
	e = fmt.Errorf("No command with name %s", name)
	return
}

func NoMngWithType(name, tpe string) (e error) {
	e = fmt.Errorf("No %s with name %s", tpe, name)
	return
}

func NoMngWithName(name string) (e error) {
	e = fmt.Errorf("No manager with name %s", name)
	return
}

func (s *manager) admin(cmd *AdmCmd) (r string, e error) {
	_, e = checkAdmin(cmd.Secret, s.crypt, s.admins)
	if e == nil {
		var mng *Mng
		if cmd.Cmd == "add" {
			switch cmd.MngType {
			case "sm":
				var sm *SessionMng
				sm = newSessionMng(cmd.Manager, s.admins, s.crypt, s.adcf)
				mng = &Mng{
					Admin: sm,
					IPM:   sm,
				}

			case "tr":
				tr := &trCons{
					NameF: cmd.Manager,
					Span:  cmd.Rule.Span,
					clock: s.clock,
				}
				mng = &Mng{
					Admin: tr,
					Cr:    tr,
				}
			case "bw":
				bw := newBwCons(cmd.Manager, cmd.FillInterval, cmd.Capacity)
				mng = &Mng{
					Admin: bw,
					Cr:    bw,
				}
			case "dw":
				m, ok := s.mngs[cmd.IPUser]
				var iu IPUser
				if ok {
					iu, ok = m.IPM.(IPUser)
				}
				if ok {
					dw := &dwnCons{
						NameF:   cmd.MngName,
						iu:      iu,
						usrCons: new(sync.Map),
						Limit:   cmd.Limit,
					}
					mng = &Mng{
						Admin: dw,
						Cr:    dw,
					}
				}
			case "cn":
				cn := &connCons{
					ipAmount: new(sync.Map),
					Limit:    uint32(cmd.Limit),
				}
				mng = &Mng{
					Admin: cn,
					Cr:    cn,
				}
			case "id":
				id := &idCons{
					NameF: cmd.Manager,
				}
				mng = &Mng{
					Admin: id,
					Cr:    id,
				}
			case "ng":
				ng := &negCons{
					NameF: cmd.Manager,
				}
				mng = &Mng{
					Admin: ng,
					Cr:    ng,
				}
			}
			if e == nil {
				name := ""
				if mng.Cr != nil {
					name = mng.Cr.Name()
				} else if mng.IPM != nil {
					name = mng.IPM.Name()
				}
				if name != "" {
					s.mngs[name] = mng
				} else {
					e = NoMngWithType("main", "ConsR or IPMatcher")
				}
			}
		} else if cmd.Cmd == "del" {
			_, ok := s.mngs[cmd.Manager]
			if ok {
				delete(s.mngs, cmd.Manager)
				// TODO update rules (delete a rule if a manager belonging to
				// it is deleted?)
			} else {
				e = NoMngWithName(cmd.Manager)
			}
		} else if cmd.Cmd == "show" {
			// TODO
			// MarshalJSON implementation for mngs's elements?
			var bs []byte
			bs, e = json.Marshal(s.mngs)
			if e == nil {
				r = string(bs)
			}
		}
	}
	return
}

func checkAdmin(secret string, c *Crypt, adms []string) (user string,
	e error) {
	user, e = c.Decrypt(secret)
	if e == nil {
		b := false
		for i := 0; !b && i != len(adms); i++ {
			b = adms[i] == user
		}
		if !b {
			e = NoAdmin(user)
		}
	}
	return
}

func NoAdmin(user string) (e error) {
	e = fmt.Errorf("No administrator with name %s", user)
	return
}
