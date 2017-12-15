package pmproxy

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	h "net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

func notSuppMeth(m string) (e error) {
	e = fmt.Errorf("Not supported method %s", m)
	return
}

func writeErr(w h.ResponseWriter, e error) {
	if e != nil {
		// The order of the following commands matter since
		// httptest.ResponseRecorder ignores parameter sent
		// to WriteHeader if Write was called first
		w.WriteHeader(h.StatusBadRequest)
		w.Write([]byte(e.Error()))
	}
}

// Decode decodes an io.Reader with a JSON formatted object
func Decode(r io.Reader, v interface{}) (e error) {
	var bs []byte
	bs, e = ioutil.ReadAll(r)
	if e == nil {
		e = json.Unmarshal(bs, v)
	}
	return
}

// Encode encodes an object in JSON notation into w
func Encode(w io.Writer, v interface{}) (e error) {
	cd := json.NewEncoder(w)
	cd.SetIndent("	", "")
	e = cd.Encode(v)
	return
}

// JWTCrypt is the object for encrypting JWT
type JWTCrypt struct {
	pKey *rsa.PrivateKey
}

// JWTUser adds jwt.StandardClaims to an User
type JWTUser struct {
	User string `json:"user"`
	jwt.StandardClaims
}

// NewJWTCrypt creates a new JWTCrypt
func NewJWTCrypt(p *rsa.PrivateKey) (j *JWTCrypt) {
	j = &JWTCrypt{pKey: p}
	return
}

func (j *JWTCrypt) encrypt(usr string) (s string, e error) {
	uc := &JWTUser{User: usr}
	t := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	s, e = t.SignedString(j.pKey)
	return
}

// checkUser checks if the signature is ok
func (j *JWTCrypt) checkUser(s string) (u string, e error) {
	t, e := jwt.ParseWithClaims(s, &JWTUser{},
		func(x *jwt.Token) (a interface{}, d error) {
			a, d = &j.pKey.PublicKey, nil
			return
		})
	var clm *JWTUser
	if e == nil {
		var ok bool
		clm, ok = t.Claims.(*JWTUser)
		if !ok {
			e = fmt.Errorf("False JWTUser type assertion")
		}
	}
	if e == nil {
		u = clm.User
	}
	return
}

// AuthHd header key of JWT value
const AuthHd = "authHd"

func (j *JWTCrypt) getUser(a h.Header) (u string, e error) {
	s := a.Get(AuthHd)
	if s == "" {
		e = fmt.Errorf("Malformed header")
	}
	if e == nil {
		u, e = j.checkUser(s)
	}
	return
}
