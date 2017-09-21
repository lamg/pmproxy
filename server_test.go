package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
	. "net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	// ErrorServeHTTP is the error when a response of the server
	// has a code different from 200
	ErrorServeHTTP = iota
)

func initPMProxy() (p *PMProxy, e *errors.Error) {
	var qa *QAdm
	var lg *RLog
	qa, lg, e = initQARL()
	if e == nil {
		p = NewPMProxy(qa, lg)
	}
	return
}

func TestServerLogInOut(t *testing.T) {
	pm, e := initPMProxy()
	require.True(t, e == nil)
	bfrq := bytes.NewBufferString(`{"user":"a", "pass":"a"}`)
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(MethodPost, logX, bfrq)
	require.NoError(t, ec)
	rq.RemoteAddr = cocoIP + ":43"
	pm.ServeHTTP(rr, rq)
	require.Equal(t, rr.Code, StatusOK)
	scrt := rr.Header().Get(authHd)
	require.True(t, scrt != "")
	var usr *User
	usr, e = pm.qa.sm.check(cocoIP, scrt)
	require.True(t, e == nil)
	require.True(t, usr.UserName == "a" &&
		pm.qa.sm.sessions[cocoIP].Equal(usr))

	rr = httptest.NewRecorder()
	rq, ec = NewRequest(MethodDelete, logX, nil)
	require.NoError(t, ec)
	rq.RemoteAddr = cocoIP + ":43"
	rq.Header.Set(authHd, scrt)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	require.True(t, pm.qa.sm.sessions[cocoIP] == nil, "%v ≠ nil",
		pm.qa.sm.sessions[cocoIP])

	testUnsMeth(t, pm, logX, MethodConnect)
}

func loginServ() (pm *PMProxy, s string, e *errors.Error) {
	pm, e = initPMProxy()
	var ec error
	var rq *Request
	if e == nil {
		var bfrq *bytes.Buffer
		bfrq = bytes.NewBufferString(`{"user":"coco", "pass":"coco"}`)
		rq, ec = NewRequest(MethodPost, logX, bfrq)
	}
	if ec == nil {
		rq.RemoteAddr = cocoIP + ":43"
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
	rq.RemoteAddr = cocoIP + ":43"
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	nv := &nameVal{Name: "A"}
	ec = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, ec)
	dv := &nameVal{Name: "A"}
	pm.qa.getQuota(cocoIP, scrt, dv)
	require.True(t, nv.Value == dv.Value, "%d ≠ %d", nv.Value,
		dv.Value)
	t.Run("Unsupported method", func(t *testing.T) {
		testUnsMeth(t, pm, groupQuota, MethodConnect)
	})
}

func TestPutGroupQuotaHF(t *testing.T) {
	pm, scrt, e := loginServ()
	require.True(t, e == nil)
	rr := httptest.NewRecorder()
	bf := bytes.NewBufferString(`{"name":"A","value":1024}`)
	rq, ec := NewRequest(MethodPut, groupQuota, bf)
	require.NoError(t, ec)
	rq.Header.Set(authHd, scrt)
	rq.RemoteAddr = cocoIP + ":43"
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
	rq.RemoteAddr = cocoIP + ":43"
	setQV(rq.URL, userV, coco.User)
	pm.ServeHTTP(rr, rq)
	nv := new(nameVal)
	ec = json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, ec)
	dv, ok := pm.qa.uc.load(coco.User)
	require.True(t, ok)
	require.True(t, nv.Value == dv)

	testUnsMeth(t, pm, userCons, MethodConnect)
}

func TestCode(t *testing.T) {
	bf := bytes.NewBufferString("")
	e := encode(bf, make(chan int, 0))
	require.True(t, e != nil && e.Code == ErrorEncode)
	e = decode(bf, 0)
	require.True(t, e != nil && e.Code == ErrorDecode)
}

func TestGoogleReq(t *testing.T) {
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(MethodGet, "https://google.com", nil)
	require.NoError(t, ec)
	pm, e := initPMProxy()
	require.True(t, e == nil)
	pm.ServeHTTP(rr, rq)
	// FIXME rr.Code = 500 when there's no network connection
	require.True(t, rr.Code == StatusForbidden,
		"Code: %d", rr.Code)
}

func setQV(u *url.URL, k, v string) {
	vs := u.Query()
	vs.Set(k, v)
	u.RawQuery = vs.Encode()
}

func testUnsMeth(t *testing.T, pm *PMProxy, path, meth string) {
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(meth, path, nil)
	require.NoError(t, ec)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusBadRequest)
}

func TestTrimPort(t *testing.T) {
	s := []struct {
		pa string
		r  string
	}{
		{"10.1.2.3:443", "10.1.2.3"},
		{"[::1]:60630", "[::1]"},
	}
	for i, j := range s {
		x := trimPort(j.pa)
		require.True(t, x == j.r, "At %d %s≠%s", i, x, j.r)
	}
}
