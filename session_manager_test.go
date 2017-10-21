package pmproxy

import (
	"github.com/lamg/ldaputil"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	coco   = &credentials{"coco", "coco"}
	pepe   = &credentials{"pepe", "pepe"}
	cocoIP = "0.0.0.0"
	pepeIP = "1.1.1.1"
)

func TestSessionManager(t *testing.T) {
	pKey, e := parseKey()
	require.True(t, e == nil)
	a, c := NewDAuth(), NewJWTCrypt(pKey)
	sm := NewSMng(a, c)
	tss := []struct {
		cr   *credentials
		ip   string
		ok   bool
		code int
	}{
		{coco, cocoIP, true, 0},
		{&credentials{"a", "b"}, pepeIP, false,
			ldaputil.ErrorAuth},
	}
	for _, j := range tss {
		lr, e := sm.login(j.cr, j.ip)
		require.True(t, (e == nil) == j.ok)
		if j.ok {
			var lu *User
			lu, e = sm.check(j.ip, lr.Scrt)
			require.True(t, e == nil)
			require.True(t, lu.UserName == j.cr.User)
		} else {
			require.True(t, e.Code == j.code)
		}
	}
	lr0, _ := sm.login(coco, cocoIP)
	lr1, _ := sm.login(coco, pepeIP)
	_, e = sm.check(cocoIP, lr0.Scrt)
	require.True(t, e.Code == errorCheck)
	_, e = sm.check(pepeIP, lr1.Scrt)
	require.True(t, e == nil)
}
