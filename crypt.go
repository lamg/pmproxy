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

package pmproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"hash"
)

type crypt struct {
	key   *rsa.PrivateKey
	hs    hash.Hash
	label []byte
}

func newCrypt() (c *crypt, e error) {
	c = new(crypt)
	c.key, e = rsa.GenerateKey(rand.Reader, 128)
	if e == nil {
		c.hs = sha512.New()
		c.label = []byte("crypto")
	}
	return
}

func (c *crypt) encrypt(s string) (bs []byte, e error) {
	bs, e = rsa.EncryptOAEP(c.hs, rand.Reader, &c.key.PublicKey,
		[]byte(s), c.label)
	return
}

func (c *crypt) decrypt(s string) (r string, e error) {
	var bs []byte
	bs, e = rsa.DecryptOAEP(c.hs, rand.Reader, c.key, []byte(s),
		c.label)
	if e == nil {
		r = string(bs)
	}
	return
}
