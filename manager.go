package pmproxy

import (
	"fmt"
)

type manager struct {
	adms map[string]Admin
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
	switch cmd.Cmd {
	case "add":
	case "del":
	}
	return
}
