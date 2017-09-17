package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
	"time"
)

func initQARL() (qa *QAdm, rl *RLog, e *errors.Error) {
	// init of l
	var bf *bytes.Buffer
	bf = bytes.NewBufferString(accR)
	var l []AccExcp
	l, e = ReadAccExcp(bf)
	var pKey *rsa.PrivateKey
	if e == nil {
		pKey, e = parseKey()
	}

	sm := new(SMng)
	if e == nil {
		da, cry := new(dAuth), new(JWTCrypt)
		da.init()
		cry.Init(pKey)
		sm.Init(da, cry)
	}

	var gq *MapPrs
	if e == nil {
		gq, e = NewMapPrs(bytes.NewBufferString(quota),
			w.NewDWF(), time.Now(), time.Second)
	}

	var uc *MapPrs
	if e == nil {
		uc, e = NewMapPrs(bytes.NewBufferString(cons),
			w.NewDWF(), time.Now(), time.Second)
	}
	qa = NewQAdm(sm, gq, uc, l, time.Now(), time.Second)
	// rl initialization
	rl = NewRLog(w.NewDWF(), sm)
	return
}

func TestProxy(t *testing.T) {
	qa, rl, e := initQARL()
	require.True(t, e == nil)
	p := newProxy(qa, rl)
	rr := ht.NewRecorder()
	rq, ec := h.NewRequest(h.MethodGet, "https://google.com", nil)
	rq.RemoteAddr = cocoIP
	require.NoError(t, ec)
	p.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusForbidden)
	var s string
	s, e = p.qa.login(pepe, pepeIP)
	require.True(t, !qa.finishedQuota(pepeIP))
	require.True(t, e == nil)
	rr = ht.NewRecorder()
	rq.RemoteAddr = pepeIP
	var n, nv uint64
	n, e = p.qa.userCons(pepeIP, s, pepe.User)
	require.True(t, e == nil)
	p.ServeHTTP(rr, rq)
	nv, e = p.qa.userCons(pepeIP, s, pepe.User)
	require.True(t, e == nil)
	require.True(t, (rr.Code == h.StatusOK && nv > n) ||
		rr.Code == h.StatusNotFound)
	//TODO test with network connection
}
