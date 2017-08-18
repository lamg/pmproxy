package pmproxy

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type JWTCrypt struct {
	pKey crypto.PrivateKey
}

type JWTUser struct {
	*User `json:"user"`
	jwt.StandardClaims
}

func (j *JWTCrypt) Init(p crypto.PrivateKey) {
	j.pKey = p
}

func (j *JWTCrypt) Encrypt(u *User) (s string, e error) {
	var t *jwt.Token
	//TODO u must embed claims
	var uc *JWTUser
	uc = &JWTUser{u, new(jwt.StandardClaims)}
	t = jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	s, e = t.SignedString(j.pKey)
	return
}

func (j *JWTCrypt) Decrypt(s string) (u *User, e error) {
	var t *jwt.Token
	t, e = jwt.Parse(s,
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = p, nil
			return
		})
	if !t.Valid {
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
	if ok {
		u, ok = clm["user"].(*User)
		if !ok {
			e = errors.New("False *User type assertion")
		}
	}
	return
}
