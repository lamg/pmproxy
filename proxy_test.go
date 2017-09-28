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
	p := NewPMProxy(qa, rl, new(NetDialer))
	rr := ht.NewRecorder()
	_, e = p.qa.login(coco, cocoIP)
	rr, rq := reqres(t, h.MethodGet, "https://twitter.com",
		"", "", cocoIP)
	p.ServeHTTP(rr, rq)
	// FIXME rr.Code = 500 when there's no network connection
	require.True(t, rr.Code == h.StatusForbidden ||
		rr.Code == h.StatusInternalServerError,
		"Code: %d", rr.Code)
	// since coco has finished his quota
	// and the requested url consumes quota

	var s string
	s, e = p.qa.login(pepe, pepeIP)
	require.True(t, !qa.nlf(pepeIP))

	var n, m uint64
	// n0 is consumption before making request
	// n1 is consumption after making request
	n, e = p.qa.userCons(pepeIP, s)
	require.True(t, e == nil)
	require.True(t, p.qa.canReq(pepeIP, "twitter.com", "443",
		time.Now()) == 1)
	rr, rq = reqres(t, h.MethodGet, "https://twitter.com",
		"", "", pepeIP)

	p.ServeHTTP(rr, rq)
	m, e = p.qa.userCons(pepeIP, s)
	require.True(t, e == nil)
	require.True(t, (rr.Code == h.StatusOK && m >= n) ||
		rr.Code == h.StatusInternalServerError,
		"Code:%d n1 >= n0: %t", rr.Code, m >= n)
}

func TestLocalRequest(t *testing.T) {
	rr, rq := reqres(t, h.MethodGet, "/", "", "", cocoIP)
	pm, e := initPMProxy()
	require.True(t, e == nil)
	pm.ServeHTTP(rr, rq)
	rs := rr.Result()
	require.True(t, rs.StatusCode == h.StatusNotFound)

	rr, rq = reqres(t, h.MethodGet, userStatus, "", "", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusBadRequest)
}

func TestForbiddenReq(t *testing.T) {
	pm, e := initPMProxy()
	require.True(t, e == nil)
	rr, rq := reqres(t, h.MethodGet, "https://twitter.com", "",
		"", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusForbidden &&
		rr.Body.String() == "No tiene acceso",
		"Code: %d", rr.Code)
}
