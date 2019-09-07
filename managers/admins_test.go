package managers

import (
	alg "github.com/lamg/algorithms"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAdmins(t *testing.T) {
	adms := &admins{
		admins: []string{"pepe", "coco"},
	}
	mng := newManager()
	mng.mngs.Store(adminsMng, adms.exec)
	iu := newIpUser()
	mng.mngs.Store(ipUserMng, iu.exec)
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
			Manager: adminsMng,
			Cmd:     isAdminK,
			IP:      ts[i].ip,
		}
		mng.exec(c)
		require.True(t, c.defined(isAdminK))
		require.Equal(t, ts[i].isAdm, c.IsAdmin)
	}
	alg.Forall(inf, len(ts))
}
