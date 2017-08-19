package pmproxy

import (
	"crypto/rsa"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

const (
	coco = "coco"
	pepe = "pepe"
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
	s0, e = sm.Login(coco, "0.0.0.0", coco)
	require.NoError(t, e)
	e = sm.Check(s0, coco)
	require.NoError(t, e)
	e = sm.Check(s0, pepe)
	require.Error(t, e)
	var s1 string
	s1, e = sm.Login(pepe, "1.1.1.1", "bla")
	require.Error(t, e)
	s1, e = sm.Login(pepe, "2.2.2.2", pepe)
	require.NoError(t, e)
	e = sm.Logout(coco, coco)
	require.NoError(t, e)
	e = sm.Check(s0, coco)
	require.Error(t, e)
	e = sm.Check(s1, pepe)
	require.NoError(t, e)
}

type dAuth struct {
}

func (d *dAuth) Authenticate(user Name, pass string) (e error) {
	if string(user) != pass {
		e = fmt.Errorf("Wrong password for %s", user)
	}
	return
}
