package pmproxy

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

type User struct {
	UserName   string `json:"userName"`
	Name       string `json:"name"`
	IsAdmin    bool   `json:"isAdmin"`
	QuotaGroup string `json:"quotaGroup"`
}

func (u *User) Equal(v interface{}) (ok bool) {
	var lu *User
	lu, ok = v.(*User)
	if ok {
		ok = u.Name == lu.Name && u.IsAdmin == lu.IsAdmin &&
			u.QuotaGroup == lu.QuotaGroup && u.UserName == lu.UserName
	}
	return
}

type JWTCrypt struct {
	pKey *rsa.PrivateKey
}

type JWTUser struct {
	User *User `json:"user"`
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
	t, e = jwt.ParseWithClaims(s, &JWTUser{},
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = &j.pKey.PublicKey, nil
			return
		})
	if e == nil && !t.Valid {
		e = fmt.Errorf("Invalid token in \"%s\"", s)
	}
	var ok bool
	var clm *JWTUser
	if e == nil {
		clm, ok = t.Claims.(*JWTUser)
		if !ok {
			e = errors.New("False jwt.MapClaims type assertion")
		}
	}
	if e == nil {
		u = clm.User
	}
	return
}
