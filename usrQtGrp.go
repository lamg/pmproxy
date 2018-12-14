package pmproxy

import (
	"sync"
)

type usrQtGrp struct {
	Name string `json: "name"`
}

type usrQt func(string) uint64

func newUsrQt(qs *sync.Map, ug usrGrp) (u usrQt, a Admin) {
	return
}
