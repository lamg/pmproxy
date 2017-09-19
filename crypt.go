package pmproxy

import (
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/errors"
)

const (
	// ErrorParseJWT is the error when parsing a JWT
	ErrorParseJWT = iota
	// ErrorNotJWTUser is the error when a JWTUser type
	// assertion fails
	ErrorNotJWTUser
	// ErrorNotValidJWT is the error when the JWT isn't valid
	ErrorNotValidJWT
	// ErrorParseRSAPrivateFromPEM is the error when calling
	// jwt.ParseRSAPrivateKeyFromPEM returns an error
	ErrorParseRSAPrivateFromPEM
	// ErrorEncrypt is the error when Encrypt fails
	ErrorEncrypt
)

// User is the type representing a logged user into the
// system
type User struct {
	UserName   string `json:"userName"`
	Name       string `json:"name"`
	IsAdmin    bool   `json:"isAdmin"`
	QuotaGroup string `json:"quotaGroup"`
}

// Equal says whether this user is equal to
// another
func (u *User) Equal(v interface{}) (ok bool) {
	var lu *User
	lu, ok = v.(*User)
	if ok {
		ok = u.Name == lu.Name && u.IsAdmin == lu.IsAdmin &&
			u.QuotaGroup == lu.QuotaGroup && u.UserName == lu.UserName
	}
	return
}

// JWTCrypt is the object for encrypting JWT
type JWTCrypt struct {
	pKey *rsa.PrivateKey
}

// JWTUser adds jwt.StandardClaims to an User
type JWTUser struct {
	User *User `json:"user"`
	jwt.StandardClaims
}

// NewJWTCrypt creates a new JWTCrypt
func NewJWTCrypt(p *rsa.PrivateKey) (j *JWTCrypt) {
	j = &JWTCrypt{pKey: p}
	return
}

func (j *JWTCrypt) encrypt(u *User) (s string, e *errors.Error) {
	uc := &JWTUser{User: u}
	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	var ec error
	s, ec = t.SignedString(j.pKey)
	if ec != nil {
		e = &errors.Error{
			Code: ErrorEncrypt,
			Err:  ec,
		}
	}
	return
}

// Decrypt decrypts a string representing an *User
func (j *JWTCrypt) decrypt(s string) (u *User, e *errors.Error) {
	t, ec := jwt.ParseWithClaims(s, &JWTUser{},
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = &j.pKey.PublicKey, nil
			return
		})
	if ec == nil && !t.Valid {
		e = &errors.Error{
			Code: ErrorNotValidJWT,
			Err:  fmt.Errorf("Invalid token in \"%s\"", s),
		}
	} else if ec != nil {
		e = &errors.Error{
			Code: ErrorParseJWT,
			Err:  ec,
		}
	}
	var clm *JWTUser
	if e == nil {
		var ok bool
		clm, ok = t.Claims.(*JWTUser)
		if !ok {
			e = &errors.Error{
				Code: ErrorNotJWTUser,
				Err:  fmt.Errorf("False JWTUser type assertion"),
			}
		}
	}
	if e == nil {
		u = clm.User
	}
	return
}
