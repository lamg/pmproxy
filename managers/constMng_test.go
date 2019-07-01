package managers

import (
	alg "github.com/lamg/algorithms"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestConstMng(t *testing.T) {
	iu := newIpUser()
	adms := &constMng{
		admins: []string{"pepe", "coco"},
	}
	mng := &manager{mngs: new(sync.Map)}
	mng.add(ipUserMng, iu.exec)
	mng.add(ConstMng, adms.exec)
	ts := []struct {
		user  string
		ip    string
		isAdm bool
	}{
		{"coco", "192.168.1.1", true},
		{"kiko", "192.168.1.2", false},
	}
	inf := func(i int) {
		iu.open(ts[i].ip, ts[i].user)
		c := &Cmd{
			Manager: ConstMng,
			Cmd:     isAdminK,
			IP:      ts[i].ip,
		}
		mng.exec(c)
		require.True(t, c.defined(isAdminK))
		require.Equal(t, ts[i].isAdm, c.IsAdmin)
	}
	alg.Forall(inf, len(ts))
}
