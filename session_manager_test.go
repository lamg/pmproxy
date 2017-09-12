package pmproxy

import (
	"crypto/rsa"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	coco   = &Credentials{"coco", "coco"}
	pepe   = &Credentials{"pepe", "pepe"}
	cocoIP = "0.0.0.0"
	pepeIP = "1.1.1.1"
)

func TestSessionManager(t *testing.T) {
	a, c := new(dAuth), new(JWTCrypt)
	var e error
	var pKey *rsa.PrivateKey
	pKey, e = parseKey()
	require.NoError(t, e)
	c.Init(pKey)
	sm := new(SMng)
	sm.Init(a, c)
	var s0 string
	s0, e = sm.Login(coco, cocoIP)
	require.NoError(t, e)
	var nm *User
	nm, e = sm.Check(cocoIP, s0)
	require.NoError(t, e)
	require.True(t, nm.Name == coco.User)
	var s1 string
	s1, e = sm.Login(&Credentials{"a", "b"}, pepeIP)
	require.Error(t, e)
	s1, e = sm.Login(pepe, pepeIP)
	require.NoError(t, e)
	e = sm.Logout(cocoIP, s0)
	require.NoError(t, e)
	_, e = sm.Check(pepeIP, s0)
	require.Error(t, e)
	nm, e = sm.Check(pepeIP, s1)
	require.NoError(t, e)
	require.True(t, nm.Name == pepe.User)
}
