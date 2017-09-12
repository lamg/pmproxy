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

func TestServer(t *testing.T) {
	// qa initialization
	qa := new(QAdm)

	// init of l
	var bf *bytes.Buffer
	bf = bytes.NewBufferString(accR)
	var l []AccExcp
	var e error
	l, e = ReadAccExcp(bf)
	require.NoError(t, e)

	// init of sm
	sm, dAuth, cry := new(SMng), new(dAuth), new(JWTCrypt)
	dAuth.Init()

	var pKey *rsa.PrivateKey
	pKey, e = parseKey()
	require.NoError(t, e)
	cry.Init(pKey)
	sm.Init(dAuth, cry)

	// init of gq
	gq := NewMapPrs(bytes.NewBufferString(quota),
		NewDWF(), time.Now(), time.Second)

	// init of uc
	uc := NewMapPrs(bytes.NewBufferString(cons),
		NewDWF(), time.Now(), time.Second)

	qa.Init(sm, gq, uc, l, time.Now(), time.Second)

	// lg initialization
	lg := new(RLog)
	lg.Init(NewDWF(), sm)

	// pm initialization
	pm := new(PMProxy)
	pm.Init(qa, lg)

	// TODO
	var bfrq *bytes.Buffer
	bfrq = bytes.NewBufferString(`{"user":"a", "pass":"a"}`)
	var rr *httptest.ResponseRecorder
	var rq *Request
	rr = httptest.NewRecorder()
	rq, e = NewRequest(MethodPost, logX, bfrq)
	require.NoError(t, e)
	pm.ServeHTTP(rr, rq)
}
