package pmproxy

import (
	"crypto/rsa"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCrypt(t *testing.T) {
	j, e := newJWTCrypt()
	require.True(t, e == nil)
	c := &credentials{User: "coco", Pass: "Coco"}
	var s string
	s, e = j.encrypt(c)
	require.True(t, e == nil)
	var lc *credentials
	lc, e = j.checkUser(s)
	require.True(t, e == nil)
	require.True(t, lc.User == c.User && lc.Pass == c.Pass)
}

func TestErrCheckUser(t *testing.T) {
	j, e := newJWTCrypt()
	require.True(t, e == nil)
	_, e = j.checkUser("coco")
	require.True(t, e.Code == ErrorParseJWT)
}

func newJWTCrypt() (j *JWTCrypt, e *errors.Error) {
	var pKey *rsa.PrivateKey
	pKey, e = parseKey()
	if e == nil {
		j = NewJWTCrypt(pKey)
	}
	return
}

type nJWT struct {
	User string `json:"user"`
	jwt.StandardClaims
}

func parseKey() (pKey *rsa.PrivateKey, e *errors.Error) {
	var ec error
	pKey, ec = jwt.ParseRSAPrivateKeyFromPEM([]byte(pemKey))
	if ec != nil {
		e = &errors.Error{
			Code: ErrorParseRSAPrivateFromPEM,
			Err:  ec,
		}
	}
	return
}
