package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	. "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	. "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

const (
	// ErrorServeHTTP is the error when a response of the server
	// has a code different from 200
	ErrorServeHTTP = iota
)

func initPMProxy() (p *PMProxy, qa *QAdm, e *errors.Error) {
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
	pm, qa, e := initPMProxy()
	require.True(t, e == nil)
	bfrq := bytes.NewBufferString(`{"user":"a", "pass":"a"}`)
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(MethodPost, logX, bfrq)
	require.NoError(t, ec)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.Equal(t, rr.Code, StatusOK)
	scrt := rr.Header().Get(authHd)
	require.True(t, scrt != "")
	var usr *User
	usr, e = qa.sm.check(cocoIP, scrt)
	require.True(t, e == nil)
	require.True(t, usr.UserName == "a" &&
		qa.sm.sessions[cocoIP].Equal(usr))

	rr = httptest.NewRecorder()
	rq, ec = NewRequest(MethodDelete, logX, nil)
	require.NoError(t, ec)
	rq.RemoteAddr = cocoIP
	rq.Header.Set(authHd, scrt)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	require.True(t, qa.sm.sessions[cocoIP] == nil, "%v ≠ nil",
		qa.sm.sessions[cocoIP])
}

func loginServ() (pm *PMProxy, s string, e *errors.Error) {
	pm, _, e = initPMProxy()
	var ec error
	var rq *Request
	if e == nil {
		var bfrq *bytes.Buffer
		bfrq = bytes.NewBufferString(`{"user":"coco", "pass":"coco"}`)
		rq, ec = NewRequest(MethodPost, logX, bfrq)
	}
	if ec == nil {
		rq.RemoteAddr = cocoIP
		rr := httptest.NewRecorder()
		pm.ServeHTTP(rr, rq)
		if rr.Code != StatusOK {
			e = &errors.Error{
				Code: ErrorServeHTTP,
				Err:  fmt.Errorf("Code %d received", rr.Code),
			}
		} else {
			s = rr.Header().Get(authHd)
		}
	}
	return
}

func TestGetGroupQuotaHF(t *testing.T) {
	pm, scrt, e := loginServ()
	require.True(t, e == nil)
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(MethodGet, groupQuota, nil)
	require.NoError(t, ec)
	setQV(rq.URL, groupV, "A")
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	nv := &nameVal{Name: "A"}
	ec = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, ec)
	dv := &nameVal{Name: "A"}
	pm.qa.getQuota(cocoIP, scrt, dv)
	require.True(t, nv.Value == dv.Value, "%d ≠ %d", nv.Value,
		dv.Value)
}

func TestPutGroupQuotaHF(t *testing.T) {
	pm, scrt, e := loginServ()
	require.True(t, e == nil)
	rr := httptest.NewRecorder()
	bf := bytes.NewBufferString(`{"name":"A","value":1024}`)
	rq, ec := NewRequest(MethodPut, groupQuota, bf)
	require.NoError(t, ec)
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)

	n, ok := pm.qa.gq.load("A")
	require.True(t, ok)
	require.True(t, n == 1024)
}

func TestGetUserCons(t *testing.T) {
	pm, scrt, e := loginServ()
	require.True(t, e == nil)
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(MethodGet, userCons, nil)
	require.NoError(t, ec)
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP
	setQV(rq.URL, userV, coco.User)
	pm.ServeHTTP(rr, rq)
	nv := new(nameVal)
	ec = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, ec)
	dv, ok := pm.qa.uc.load(coco.User)
	require.True(t, ok)
	require.True(t, nv.Value == dv)
}

func setQV(u *url.URL, k, v string) {
	vs := u.Query()
	vs.Set(k, v)
	u.RawQuery = vs.Encode()
}
