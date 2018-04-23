package pmproxy

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCrypt(t *testing.T) {
	j := NewJWTCrypt()
	c := &credentials{User: "coco", Pass: "Coco"}
	s, e := j.encrypt(c)
	require.True(t, e == nil)
	var lc *credentials
	lc, e = j.checkUser(s)
	require.NoError(t, e)
	require.True(t, lc.User == c.User && lc.Pass == c.Pass)
}

func TestErrCheckUser(t *testing.T) {
	j := NewJWTCrypt()
	_, e := j.checkUser("coco")
	require.Error(t, e)
}

type nJWT struct {
	User string `json:"user"`
	jwt.StandardClaims
}
