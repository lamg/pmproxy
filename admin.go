package pmproxy

import (
	"fmt"
)

type mngDisp struct {
	adms map[string]Admin
}

func (s *mngDisp) Exec(cmd *AdmCmd) (r string, e error) {
	adm, ok := s.adms[cmd.Manager]
	if ok {
		r, e = adm.Exec(cmd)
	} else {
		e = NoMngWithName(cmd.Manager)
	}
	return
}

func NoMngWithName(name string) (e error) {
	e = fmt.Errorf("No manager with name %s", name)
	return
}
