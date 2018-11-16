package pmproxy

import (
	"fmt"
	rl "github.com/juju/ratelimit"
	"github.com/lamg/clock"
	"sync"
	"time"
)

type manager struct {
	clock  clock.Clock
	crypt  *Crypt
	adcf   *adConf
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

type adConf struct {
	user string
	pass string
	addr string
	bdn  string
	suff string
}

func (s *manager) Exec(cmd *AdmCmd) (r string, e error) {
	adm, ok := s.mngs[cmd.Manager]
	if ok {
		r, e = adm.Exec(cmd)
	} else if cmd.Manager == "" {
		e = s.admin(cmd)
	} else if cmd.Manager == "rules" {
		if cmd.Cmd == "add" {
			// conversion from *JRule to *Rule
			var rule *Rule
			if cmd.Rule != nil {
				rule = &Rule{
					Unit: cmd.Rule.Unit,
					span: cmd.Rule.Span,
					Spec: &Spec{
						Iface:    cmd.Rule.Spec.Iface,
						ProxyURL: cmd.Rule.Spec.ProxyURL,
						Cr:       make([]ConsR, 0),
					},
				}
				if cmd.Rule.IPM != "" {
					mng, ok := s.mngs[cmd.Rule.IPM]
					if ok && mng.IPM != nil {
						rule.IPM = mng.IPM
					} else if !ok {
						e = NoMngWithName(cmd.Rule.IPM)
					} else if mng.IPM == nil {
						e = NoMngWithType(cmd.Rule.IPM, "IPMatcher")
					}
				}
				for i := 0; e == nil && i != len(cmd.Rule.Spec.ConsR); i++ {
					mng, ok := s.mngs[cmd.Rule.Spec.ConsR[i]]
					if ok && mng.Cr != nil {
						rule.Spec.Cr = append(rule.Spec.Cr, mng.Cr)
					} else if !ok {
						e = NoMngWithName(cmd.Rule.Spec.ConsR[i])
					} else if mng.Cr == nil {
						e = NoMngWithType(cmd.Rule.Spec.ConsR[i], "ConsR")
					}
				}
			} else {
				e = InvalidArgs(cmd)
			}
			if e == nil {
				// TODO
			}
		} else if cmd.Cmd == "del" {
			// TODO
		}
	} else {
		e = NoMngWithName(cmd.Manager)
	}
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

func (s *manager) admin(cmd *AdmCmd) (e error) {
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
					name:  cmd.Manager,
					span:  cmd.Rule.Span,
					clock: s.clock,
				}
				mng = &Mng{
					Admin: tr,
					Cr:    tr,
				}
			case "bw":
				bw := &bwCons{
					name: cmd.Manager,
					rl:   rl.NewBucket(time.Duration(cmd.FillInterval), cmd.Capacity),
				}
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
						name:    cmd.MngName,
						iu:      iu,
						usrCons: new(sync.Map),
						limit:   cmd.Limit,
					}
					mng = &Mng{
						Admin: dw,
						Cr:    dw,
					}
				}
			case "cn":
				cn := &connCons{
					ipAmount: new(sync.Map),
					limit:    uint32(cmd.Limit),
				}
				mng = &Mng{
					Admin: cn,
					Cr:    cn,
				}
			case "id":
				id := &idCons{
					name: cmd.Manager,
				}
				mng = &Mng{
					Admin: id,
					Cr:    id,
				}
			case "ng":
				ng := &negCons{
					name: cmd.Manager,
				}
				mng = &Mng{
					Admin: ng,
					Cr:    ng,
				}
			}
			if e == nil {
				s.mngs[mng.Name()] = mng
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
