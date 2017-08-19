package pmproxy

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type JWTCrypt struct {
	pKey *rsa.PrivateKey
}

type JWTUser struct {
	*User `json:"user"`
	jwt.StandardClaims
}

func (j *JWTCrypt) Init(p *rsa.PrivateKey) {
	j.pKey = p
}

func (j *JWTCrypt) Encrypt(u *User) (s string, e error) {
	var t *jwt.Token
	var uc *JWTUser
	uc = &JWTUser{User: u}
	t = jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	s, e = t.SignedString(j.pKey)
	return
}

func (j *JWTCrypt) Decrypt(s string) (u *User, e error) {
	var t *jwt.Token
	t, e = jwt.Parse(s,
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = &j.pKey.PublicKey, nil
			return
		})
	if e == nil && !t.Valid {
		e = fmt.Errorf("Invalid token in \"%s\"", s)
	}
	var ok bool
	var clm jwt.MapClaims
	if e == nil {
		clm, ok = t.Claims.(jwt.MapClaims)
		if !ok {
			e = errors.New("False jwt.MapClaims type assertion")
		}
	}
	var usm map[string]interface{}
	if ok {
		usm, ok = clm["user"].(map[string]interface{})
		if !ok {
			e = errors.New("False *User type assertion")
		}
	}
	if e == nil {
		u = &User{
			Name:    usm["name"].(string),
			IsAdmin: usm["isAdmin"].(bool),
		}
	}
	return
}
