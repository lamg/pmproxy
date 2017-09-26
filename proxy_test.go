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
	lh := newLocalHn(qa)
	p := NewPMProxy(qa, rl, lh)
	rr := ht.NewRecorder()
	_, e = p.qa.login(coco, cocoIP)
	rr, rq := reqres(t, h.MethodGet, "https://google.com",
		"", "", cocoIP)
	p.ServeHTTP(rr, rq)
	// FIXME rr.Code = 500 when there's no network connection
	require.True(t, rr.Code < h.StatusForbidden ||
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
	nv := new(nameVal)
	e = p.qa.userCons(pepeIP, s, nv)
	require.True(t, e == nil)
	n = nv.Value
	rr, rq = reqres(t, h.MethodGet, "https://google.com",
		"", "", pepeIP)
	p.ServeHTTP(rr, rq)
	e = p.qa.userCons(pepeIP, s, nv)
	require.True(t, e == nil)
	m = nv.Value
	require.True(t, (rr.Code < h.StatusForbidden && m >= n) ||
		rr.Code == h.StatusNotFound ||
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
}

func TestNewConCount(t *testing.T) {
	// create a proxy type that instead of using
	// net.Dial directly, uses an interface for
	// dialing
}

func TestGoogleReq(t *testing.T) {
	rr, rq := reqres(t, h.MethodGet, "https://google.com", "",
		"", cocoIP)
	pm, e := initPMProxy()
	require.True(t, e == nil)
	pm.ServeHTTP(rr, rq)
	// FIXME rr.Code = 500 when there's no network connection
	// FIXME use recres
	require.True(t, rr.Code == h.StatusForbidden ||
		rr.Code == h.StatusInternalServerError,
		"Code: %d", rr.Code)
}
