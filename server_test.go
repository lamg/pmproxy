package pmproxy

import (
	"bytes"
	"crypto/rsa"
	. "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	. "net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func initPMProxy() (p *PMProxy, qa *QAdm, e error) {
	// qa initialization
	qa = new(QAdm)

	// init of l
	var bf *bytes.Buffer
	bf = bytes.NewBufferString(accR)
	var l []AccExcp
	l, e = ReadAccExcp(bf)
	var pKey *rsa.PrivateKey
	if e == nil {
		pKey, e = parseKey()
	}

	var sm *SMng
	if e == nil {
		var da *dAuth
		var cry *JWTCrypt
		// init of sm
		sm, da, cry = new(SMng), new(dAuth), new(JWTCrypt)
		da.Init()
		cry.Init(pKey)
		sm.Init(da, cry)
	}

	var gq *MapPrs
	if e == nil {
		gq, e = NewMapPrs(bytes.NewBufferString(quota),
			NewDWF(), time.Now(), time.Second)
	}

	var uc *MapPrs
	if e == nil {
		uc, e = NewMapPrs(bytes.NewBufferString(cons),
			NewDWF(), time.Now(), time.Second)
	}

	if e == nil {
		qa.Init(sm, gq, uc, l, time.Now(), time.Second)
		// lg initialization
		lg := new(RLog)
		lg.Init(NewDWF(), sm)
		// pm initialization
		p = new(PMProxy)
		p.Init(qa, lg)
	}
	return
}

func TestServerLogInOut(t *testing.T) {
	var pm *PMProxy
	var qa *QAdm
	var e error
	pm, qa, e = initPMProxy()
	var bfrq *bytes.Buffer
	bfrq = bytes.NewBufferString(`{"user":"a", "pass":"a"}`)
	var rr *httptest.ResponseRecorder
	var rq *Request
	rr = httptest.NewRecorder()
	rq, e = NewRequest(MethodPost, logX, bfrq)
	require.NoError(t, e)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.Equal(t, rr.Code, StatusOK)
	var scrt string
	scrt = rr.Header().Get(authHd)
	require.True(t, scrt != "")
	var usr *User
	usr, e = qa.sm.Check(cocoIP, scrt)
	require.NoError(t, e)
	require.True(t, usr.UserName == "a" &&
		qa.sm.sessions[cocoIP].Equal(usr))

	// TODO logout
}
