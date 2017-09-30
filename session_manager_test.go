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
	var s0 string
	s0, e = sm.login(coco, cocoIP)
	require.True(t, e == nil)
	var nm *User
	nm, e = sm.check(cocoIP, s0)
	require.True(t, e == nil)
	require.True(t, nm.Name == coco.User)
	var s1 string
	s1, e = sm.login(&credentials{"a", "b"}, pepeIP)
	require.True(t, e != nil && e.Code == ldaputil.ErrorAuth)
	s1, e = sm.login(pepe, pepeIP)
	require.True(t, e == nil)
	e = sm.logout(cocoIP, s0)
	require.True(t, e == nil)
	_, e = sm.check(pepeIP, s0)
	require.Error(t, e)
	nm, e = sm.check(pepeIP, s1)
	require.True(t, e == nil)
	require.True(t, nm.Name == pepe.User)
}
