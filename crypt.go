package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/errors"
	"io"
	"strings"
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

// ToJSON encodes the instance to a JSON string
func (u *User) ToJSON() (s string, e *errors.Error) {
	sw := bytes.NewBufferString("")
	e = Encode(sw, u)
	if e == nil {
		s = sw.String()
	}
	return
}

// NewUserFR parses a JSON User representation
func NewUserFR(r io.Reader) (u *User, e *errors.Error) {
	u = new(User)
	e = Decode(r, u)
	return
}

// JWTCrypt is the object for encrypting JWT
type JWTCrypt struct {
	pKey *rsa.PrivateKey
}

// JWTUser adds jwt.StandardClaims to an User
type JWTUser struct {
	Data string `json:"data"`
	jwt.StandardClaims
}

// NewJWTCrypt creates a new JWTCrypt
func NewJWTCrypt(p *rsa.PrivateKey) (j *JWTCrypt) {
	j = &JWTCrypt{pKey: p}
	return
}

func (j *JWTCrypt) encrypt(c *credentials) (s string, e *errors.Error) {
	bf := bytes.NewBufferString("")
	e = Encode(bf, c)
	var uc *JWTUser
	if e == nil {
		uc = &JWTUser{Data: bf.String()}
	}
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

// checkUser checks if the signature is ok
func (j *JWTCrypt) checkUser(s string) (c *credentials, e *errors.Error) {
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
		} else {
			rd := strings.NewReader(clm.Data)
			c = new(credentials)
			e = Decode(rd, c)
		}
	}
	return
}
