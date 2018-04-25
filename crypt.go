package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"math/rand"
	"strings"
	//"time"
)

// User is the type representing a logged user into the
// system
type User struct {
	// user account name
	UserName string `json:"userName"`
	// person name
	Name        string   `json:"name"`
	IsAdmin     bool     `json:"isAdmin"`
	QuotaGroups []string `json:"quotaGroup"`
}

// Equal says whether this user is equal to
// another
func (u *User) Equal(v interface{}) (ok bool) {
	var lu *User
	lu, ok = v.(*User)
	if ok {
		ok = u.Name == lu.Name && u.IsAdmin == lu.IsAdmin &&
			u.UserName == lu.UserName &&
			len(u.QuotaGroups) == len(lu.QuotaGroups)
		for i := 0; ok && i != len(u.QuotaGroups); i++ {
			ok = u.QuotaGroups[i] == lu.QuotaGroups[i]
		}
	}
	return
}

// ToJSON encodes the instance to a JSON string
func (u *User) ToJSON() (s string, e error) {
	sw := bytes.NewBufferString("")
	e = Encode(sw, u)
	if e == nil {
		s = sw.String()
	}
	return
}

// NewUserFR parses a JSON User representation
func NewUserFR(r io.Reader) (u *User, e error) {
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
func NewJWTCrypt() (j *JWTCrypt) {
	x, e := rsa.GenerateKey(rand.New(rand.NewSource(43)), 1024)
	if e != nil {
		panic(e.Error())
	}
	j = &JWTCrypt{pKey: x}
	return
}

func (j *JWTCrypt) encrypt(c *credentials) (s string, e error) {
	bf := bytes.NewBufferString("")
	e = Encode(bf, c)
	if e == nil {
		uc := &JWTUser{Data: bf.String()}
		//uc.ExpiresAt = time.Now().Add(time.Hour).Unix()
		t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
		s, e = t.SignedString(j.pKey)
	}
	return
}

// checkUser checks if the signature is ok
func (j *JWTCrypt) checkUser(s string) (c *credentials, e error) {
	t, e := jwt.ParseWithClaims(s, &JWTUser{},
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = &j.pKey.PublicKey, nil
			return
		})
	if e == nil && !t.Valid {
		e = fmt.Errorf("Invalid token in \"%s\"", s)
	}
	var clm *JWTUser
	if e == nil {
		var ok bool
		clm, ok = t.Claims.(*JWTUser)
		if !ok {
			e = fmt.Errorf("False JWTUser type assertion")
		} else {
			rd := strings.NewReader(clm.Data)
			c = new(credentials)
			e = Decode(rd, c)
		}
	}
	return
}
