// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package managers

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	alg "github.com/lamg/algorithms"
	"time"
)

type crypt struct {
	key        *rsa.PrivateKey
	expiration time.Duration
}

const (
	cryptMng = "crypt"
	encrypt  = "encrypt"
	decrypt  = "decrypt"
	secretOk = "secretOk"
	Renew    = "renew"
)

var ErrClaims = fmt.Errorf("invalid claims")

func newCrypt(exp time.Duration) (c *crypt, e error) {
	c = &crypt{
		expiration: exp,
	}
	c.key, e = rsa.GenerateKey(rand.Reader, 1024)
	return
}

type claim struct {
	User string `json:"user"`
	DB   string `json:"db"`
	jwt.StandardClaims
}

func (c *crypt) encrypt(user, db string) (s string, e error) {
	expt := time.Now().Add(c.expiration)
	uc := &claim{
		User: user,
		DB:   db,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expt.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	s, e = token.SignedString(c.key)
	return
}

func (c *crypt) decrypt(s string) (user *claim, e error) {
	token, e := jwt.ParseWithClaims(s, new(claim),
		func(t *jwt.Token) (i interface{}, e error) {
			i = &c.key.PublicKey
			return
		},
	)
	if token != nil {
		var ok bool
		user, ok = token.Claims.(*claim)
		if !ok {
			e = ErrClaims
		}
	}
	return
}

func (c *crypt) exec(m *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			encrypt,
			func() {
				m.Secret, m.Err = c.encrypt(m.User, "")
			},
		},
		{
			decrypt,
			func() {
				var cl *claim
				cl, m.Err = c.decrypt(m.Secret)
				if m.Err == nil {
					m.String = cl.User
				}
			},
		},
	}
	alg.ExecF(kf, m.Cmd)
	term = true
	return
}
