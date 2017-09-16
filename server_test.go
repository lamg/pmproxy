package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	. "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	. "net/http"
	"net/http/httptest"
	"net/url"
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
		p = NewPMProxy(qa, lg)
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

	rr = httptest.NewRecorder()
	rq, e = NewRequest(MethodDelete, logX, nil)
	require.NoError(t, e)
	rq.RemoteAddr = cocoIP
	rq.Header.Set(authHd, scrt)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	require.True(t, qa.sm.sessions[cocoIP] == nil, "%v ≠ nil",
		qa.sm.sessions[cocoIP])
}

func loginServ() (pm *PMProxy, s string, e error) {
	pm, _, e = initPMProxy()
	var rq *Request
	if e == nil {
		var bfrq *bytes.Buffer
		bfrq = bytes.NewBufferString(`{"user":"coco", "pass":"coco"}`)
		rq, e = NewRequest(MethodPost, logX, bfrq)
	}
	if e == nil {
		rq.RemoteAddr = cocoIP
		var rr *httptest.ResponseRecorder
		rr = httptest.NewRecorder()
		pm.ServeHTTP(rr, rq)
		if rr.Code != StatusOK {
			e = fmt.Errorf("Code %d received", rr.Code)
		} else {
			s = rr.Header().Get(authHd)
		}
	}
	return
}

func TestGetGroupQuotaHF(t *testing.T) {
	var pm *PMProxy
	var scrt string
	var e error
	pm, scrt, e = loginServ()
	require.NoError(t, e)
	var rr *httptest.ResponseRecorder
	rr = httptest.NewRecorder()
	var rq *Request
	rq, e = NewRequest(MethodGet, groupQuota, nil)
	require.NoError(t, e)
	setQV(rq.URL, groupV, "A")
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	nv := &NameVal{Name: "A"}
	e = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, e)
	dv := &NameVal{Name: "A"}
	pm.qa.GetQuota(cocoIP, scrt, dv)
	require.True(t, nv.Value == dv.Value, "%d ≠ %d", nv.Value,
		dv.Value)
}

func TestPutGroupQuotaHF(t *testing.T) {
	var pm *PMProxy
	var scrt string
	var e error
	pm, scrt, e = loginServ()
	require.NoError(t, e)
	var rr *httptest.ResponseRecorder
	rr = httptest.NewRecorder()
	var bf *bytes.Buffer
	bf = bytes.NewBufferString(`{"name":"A","value":1024}`)
	var rq *Request
	rq, e = NewRequest(MethodPut, groupQuota, bf)
	require.NoError(t, e)
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	var n uint64
	var ok bool
	n, ok = pm.qa.gq.Load("A")
	require.True(t, ok)
	require.True(t, n == 1024)
}

func TestGetUserCons(t *testing.T) {
	pm, scrt, e := loginServ()
	rr := httptest.NewRecorder()
	var rq *Request
	rq, e = NewRequest(MethodGet, userCons, nil)
	require.NoError(t, e)
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	setQV(rq.URL, userV, coco.User)
	pm.ServeHTTP(rr, rq)
	nv := new(NameVal)
	e = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, e)
	dv, ok := pm.qa.uc.Load(coco.User)
	require.True(t, ok)
	require.True(t, nv.Value == dv)
}

func setQV(u *url.URL, k, v string) {
	vs := u.Query()
	vs.Set(k, v)
	u.RawQuery = vs.Encode()
}
