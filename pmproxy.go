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

// c: LDAP Connection used to authenticate
// pk: private key used for encrypting JSON Web Tokens
// gq: map of group quotas
// uc: map of user consumption
// qw: for gq's persistence
// cw: for uc's persistence
// lw: for log's persistence
// al: list of access restrictions
func (p *PMProxy) Init(c *ldap.Conn, pk *rsa.PrivateKey,
	al []AccRstr, gq, uc *MapPrs, rl *RLog) (e error) {
	// TODO automatic persistence of maps and log rotation
	gqr, ucr := new(QuotaRec), new(ConsRst)
	gqr.Init(gq, qw)
	ucr.Init(uc)
	// end

	// ldp initialization (shared by sm and qAdm)
	ldp := new(LdapUPR)
	ldp.Init(c)
	// end

	// sm initialization (shared by prHnd and qAdm)
	sm, crypt := new(SMng), new(JWTCrypt)
	crypt.Init(pk)
	sm.Init(ldp, crypt)
	// end

	// qAdm
	qAdm := new(QAdm)
	qAdm.Init(sm, gq, uc, al)
	// end

	// prHnd initialization
	prHnd, rl := new(PrxHnd), new(RLog)
	// sm as IPUser
	rl.iu = sm
	prHnd.Init(qAdm, rl)
	// end

	// adHnd initialization
	adHnd := new(PMAdmin)
	adHnd.Init(qAdm)
	// end

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
