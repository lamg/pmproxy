package pmproxy

import (
	"sync"
)

type admins struct {
	adms *sync.Map
}

func newAdmin(ads []*adminName) (a admin, e error) {
	adms := &admins{
		adms: new(sync.Map),
	}
	forall(func(i int) {
		adms.adms.Store(ads[i].name, ads[i].cmds)
	},
		len(ads),
	)
	a = func(cmd *admCmd) (bs []byte, e error) {
		v, ok := adms.adms.Load(cmd.AdmName)
		if ok {
			// TODO walk slice
		} else {
			e = noKey(cmd.AdmName)
		}
	}
	return
}

type adminName struct {
	name string
	cmds []kRes
}

type kRes struct {
	key string
	res func() ([]byte, error)
}
