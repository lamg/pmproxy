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

func (c *crypt) Encrypt(s string) (r string, e error) {
	var bs []byte
	bs, e = rsa.EncryptOAEP(c.hs, rand.Reader, &c.key.PublicKey,
		[]byte(s), c.label)
	if e == nil {
		r = string(bs)
	}
	return
}

func (c *crypt) Decrypt(s string) (r string, e error) {
	var bs []byte
	bs, e = rsa.DecryptOAEP(c.hs, rand.Reader, c.key, []byte(s),
		c.label)
	if e == nil {
		r = string(bs)
	}
	return
}
