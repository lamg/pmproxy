package pmproxy

import (
	"fmt"
)

type manager struct {
	crypt  *Crypt
	admins []string
	adms   map[string]Admin
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
	if cmd.Cmd == "add" {
		switch cmd.MngType {
		case "sm":

		case "tr":
		case "bw":
		case "dw":
		case "cn":
		case "id":
		case "ng":
		}
	} else if cmd.Cmd == "del" {

	}
	return
}

func checkAdmin(secret string, c *Crypt, adms []string) (e error) {
	var user string
	user, e = c.Decrypt(secret)
	if e == nil {
	}
	return
}
