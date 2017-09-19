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

	var sm *SMng
	if e == nil {
		da, cry := newdAuth(), NewJWTCrypt(pKey)
		sm = NewSMng(da, cry)
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
	qa = NewQAdm(sm, gq, uc, l, time.Now(), time.Hour)
	// rl initialization
	rl = NewRLog(w.NewDWF(), sm)
	return
}

func TestProxy(t *testing.T) {
	qa, rl, e := initQARL()
	require.True(t, e == nil)
	p := newProxy(qa, rl)
	rr := ht.NewRecorder()
	_, e = p.qa.login(coco, cocoIP)
	rq, ec := h.NewRequest(h.MethodGet, "https://google.com", nil)
	rq.RemoteAddr = cocoIP
	require.NoError(t, ec)
	p.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusForbidden, "Code: %d",
		rr.Code)
	var s string
	s, e = p.qa.login(pepe, pepeIP)
	rq.RemoteAddr = pepeIP
	require.True(t, !qa.finishedQuota(pepeIP))
	require.True(t, e == nil)
	rr = ht.NewRecorder()
	var n, nv uint64
	n, e = p.qa.userCons(pepeIP, s, pepe.User)
	require.True(t, e == nil)
	rq.RemoteAddr = pepeIP
	p.ServeHTTP(rr, rq)
	nv, e = p.qa.userCons(pepeIP, s, pepe.User)
	require.True(t, e == nil)
	require.True(t, (rr.Code < h.StatusForbidden && nv >= n) ||
		rr.Code == h.StatusNotFound, "Code:%d nv > n: %t",
		rr.Code, nv > n)
}
