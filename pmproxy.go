package pmproxy

import (
	"crypto/rsa"
	"github.com/go-ldap/ldap"
	. "net/http"
	"sync"
)

type PMProxy struct {
	adm, prx Handler
}

func (p *PMProxy) Init(c *ldap.Conn, pk *rsa.PrivateKey,
	gq, uc *sync.Map, wr WriterFct) (e error) {
	ldp := new(LdapUPR)
	ldp.Init(c)
	sm, crypt := new(SMng), new(JWTCrypt)
	crypt.Init(pk)
	sm.Init(ldp, crypt)
	qAdm := new(QAdm)
	qAdm.Init(sm, ldp, gq, uc)
	adHnd := new(PMAdmin)
	adHnd.Init(qAdm)
	prHnd, rl := new(PrxHnd), new(RLog)
	rl.Init(wr, sm)
	prHnd.Init(qAdm, rl)
	p.adm, p.prx = adHnd, prHnd
	return
}

func (p *PMProxy) ServeHTTP(w ResponseWriter, r *Request) {
	if r.URL.Host == "" {
		p.adm.ServeHTTP(w, r)
	} else {
		p.prx.ServeHTTP(w, r)
	}
}
