package pmproxy

import (
	"fmt"
)

type manager struct {
	crypt  *Crypt
	adcf   *adConf
	admins []string
	adms   map[string]Admin
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
		if cmd.Cmd == "add" {
			switch cmd.MngType {
			case "sm":
				var sm *SessionMng
				s, e = newSessionMng(s.admins, s.cr, s.adcf)
				// TODO adding sm to adms looses type information, which is
				// needed in case s becomes part of a rule
			case "tr":

			case "bw":
			case "dw":
			case "cn":
			case "id":
			case "ng":
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
