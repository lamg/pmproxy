package pmproxy

import (
	"fmt"
	"github.com/lamg/clock"
)

type manager struct {
	clock  clock.Clock
	crypt  *Crypt
	adcf   *adConf
	admins []string
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
	adm, ok := s.adms[cmd.Manager]
	if ok {
		r, e = adm.Exec(cmd)
	} else if cmd.Manager == "" {
		e = s.admin(cmd)
	} else {
		e = NoMngWithName(cmd.Manager)
	}
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
				s, e = newSessionMng(cmd.Manager, s.admins, s.cr, s.adcf)
				if e == nil {
					mng = &Mng{
						Admin: sm,
						IPM:   sm,
					}
				}
			case "tr":
				tr := &trCons{
					name:  cmd.Manager,
					span:  cmd.span,
					clock: s.clock,
				}
				mng = &Mng{
					Admin: tr,
					Cr:    tr,
				}
			case "bw":
			case "dw":
			case "cn":
			case "id":
			case "ng":
			}
			if e == nil {
				s.mngs[mng.Name()] = mng
			}
		} else if cmd.Cmd == "del" {

		}
	}
	return
}

func checkAdmin(secret string, c *Crypt, adms []string) (user string, e error) {
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
