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
	"errors"
	"github.com/dgrijalva/jwt-go"
	alg "github.com/lamg/algorithms"
	"time"
)

type crypt struct {
	key        *rsa.PrivateKey
	expiration time.Duration
}

var (
	ErrClaims  = &StringErr{"invalid claims"}
	ErrExpired = &StringErr{"expired token"}
	ErrEmpty   = &StringErr{"empty JWT"}
)

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

func (c *crypt) encrypt(user, db string) (bs []byte, e error) {
	expt := jwt.TimeFunc().Add(c.expiration)
	uc := &claim{
		User: user,
		DB:   db,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expt.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), uc)
	var s string
	s, e = token.SignedString(c.key)
	if e == nil {
		bs = []byte(s)
	}
	return
}

func (c *crypt) decrypt(s string) (user *claim, e error) {
	token, e := jwt.ParseWithClaims(s, new(claim),
		func(t *jwt.Token) (i interface{}, e error) {
			i = &c.key.PublicKey
			return
		},
	)
	if e == nil {
		var ok bool
		user, ok = token.Claims.(*claim)
		if !ok {
			e = ErrClaims
		}
	} else {
		var ve *jwt.ValidationError
		if errors.As(e, &ve) {
			if ve.Errors&jwt.ValidationErrorExpired == ve.Errors {
				e = ErrExpired
			} else if s == "" {
				e = ErrEmpty
			}
			if token != nil {
				user, _ = token.Claims.(*claim)
			}
		}
	}
	return
}

func (c *crypt) exec(m *Cmd) {
	kf := []alg.KFunc{
		{
			encrypt,
			func() {
				m.data, m.err = c.encrypt(m.loggedBy.user, "")
			},
		},
		{
			decrypt,
			func() {
				var cl *claim
				cl, m.err = c.decrypt(m.Secret)
				if m.err == nil {
					m.Info.UserName = cl.User
				}
			},
		},
		{
			Check,
			func() {
				var cl *claim
				cl, m.err = c.decrypt(m.Secret)
				if m.err == nil && cl.User != m.loggedBy.user {
					m.err = &CheckErr{
						Logged:    m.loggedBy.user,
						Decrypted: cl.User,
					}
				} else if m.err == nil {
					m.data = []byte(cl.User)
				}
			},
		},
		{
			Renew,
			func() {
				var cl *claim
				cl, m.err = c.decrypt(m.Secret)
				if cl != nil && errors.Is(m.err, ErrExpired) &&
					cl.User == m.loggedBy.user {
					m.data, m.err = c.encrypt(m.loggedBy.user, "")
				}
			},
		},
	}
	alg.ExecF(kf, m.Cmd)
}
