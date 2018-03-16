package pmproxy

import (
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
	a, c := newDAuth(), NewJWTCrypt(pKey)
	sm := NewSMng(a, c)
	tss := []struct {
		cr *credentials
		ip string
		ok bool
	}{
		{coco, cocoIP, true},
		{&credentials{"a", "b"}, pepeIP, false},
	}
	for _, j := range tss {
		lr, e := sm.login(j.cr, j.ip)
		require.True(t, (e == nil) == j.ok)
		if j.ok {
			var lc *credentials
			lc, e = sm.check(j.ip, lr.Scrt)
			require.True(t, e == nil)
			require.True(t, lc.User == j.cr.User)
		}
	}
	lr0, _ := sm.login(coco, cocoIP)
	lr1, _ := sm.login(coco, pepeIP)
	_, e = sm.check(cocoIP, lr0.Scrt)
	require.Error(t, e)
	_, e = sm.check(pepeIP, lr1.Scrt)
	require.NoError(t, e)
}

func newDAuth() (d *DAuth) {
	d = new(DAuth)
	d.us = map[string]*User{
		coco.User: &User{
			Name:        coco.User,
			UserName:    coco.User,
			IsAdmin:     true,
			QuotaGroups: []string{"A"},
		},
		pepe.User: &User{
			Name:        pepe.User,
			UserName:    pepe.User,
			IsAdmin:     true,
			QuotaGroups: []string{"A"},
		},
		"cuco": &User{
			Name:        "cuco",
			UserName:    "cuco",
			IsAdmin:     false,
			QuotaGroups: []string{"A", "B"},
		},
		"a": &User{
			Name:        "a",
			UserName:    "a",
			IsAdmin:     false,
			QuotaGroups: []string{"A"},
		},
	}
	return
}
