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
	rr, rq := reqres(t, MethodPost, logX,
		`{"user":"a", "pass":"a"}`, "", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.Equal(t, rr.Code, StatusOK)
	scrt := rr.Header().Get(authHd)
	require.True(t, scrt != "")
	var usr *User
	usr, e = pm.qa.sm.check(cocoIP, scrt)
	require.True(t, e == nil)
	require.True(t, usr.UserName == "a" &&
		pm.qa.sm.User(cocoIP).Equal(usr))

	rr, rq = reqres(t, MethodDelete, logX, "", scrt, cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	require.True(t, pm.qa.sm.User(cocoIP) == nil, "%v ≠ nil",
		pm.qa.sm.User(cocoIP))

	testUnsMeth(t, pm, logX, MethodConnect)
}

func loginServ(t *testing.T) (pm *PMProxy, s string) {
	pm, e := initPMProxy()
	require.True(t, e == nil)
	rr, rq := reqres(t, MethodPost, logX,
		`{"user":"coco", "pass":"coco"}`, "", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	s = rr.Header().Get(authHd)
	return
}

func TestGetGroupQuotaHF(t *testing.T) {
	pm, scrt := loginServ(t)
	rr, rq := reqres(t, MethodGet, groupQuota, "", scrt,
		cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	nv := &nameVal{}
	ec := json.Unmarshal(rr.Body.Bytes(), nv)
	require.NoError(t, ec)
	qg := pm.qa.sm.User(cocoIP).QuotaGroup
	dv := &nameVal{Name: qg}
	pm.qa.getQuota(cocoIP, scrt, dv)
	require.True(t, nv.Value == dv.Value, "%d ≠ %d", nv.Value,
		dv.Value)
	t.Run("Unsupported method", func(t *testing.T) {
		testUnsMeth(t, pm, groupQuota, MethodConnect)
	})
}

func TestPutGroupQuotaHF(t *testing.T) {
	pm, scrt := loginServ(t)
	rr, rq := reqres(t, MethodPut, groupQuota,
		`{"name":"A","value":1024}`, scrt, cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)

	n, ok := pm.qa.gq.load("A")
	require.True(t, ok)
	require.True(t, n == 1024)
}

func TestGetUserCons(t *testing.T) {
	pm, scrt := loginServ(t)
	rr, rq := reqres(t, MethodGet, userCons, "", scrt, cocoIP)
	pm.ServeHTTP(rr, rq)
	nv := new(nameVal)
	ec := json.Unmarshal(rr.Body.Bytes(), nv)
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
	rr, rq := reqres(t, MethodGet, "https://google.com", "",
		"", cocoIP)
	pm, e := initPMProxy()
	require.True(t, e == nil)
	pm.ServeHTTP(rr, rq)
	// FIXME rr.Code = 500 when there's no network connection
	// FIXME use recres
	require.True(t, rr.Code == StatusForbidden ||
		rr.Code == StatusInternalServerError,
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

func reqres(t *testing.T, meth, path, body, hd,
	addr string) (r *httptest.ResponseRecorder, q *Request) {
	var e error
	if body != "" {
		by := bytes.NewBufferString(body)
		q, e = NewRequest(meth, path, by)
	} else {
		q, e = NewRequest(meth, path, nil)
	}
	require.NoError(t, e)
	if hd != "" {
		q.Header.Set(authHd, hd)
	}
	q.RemoteAddr = fmt.Sprintf("%s:443", addr)
	r = httptest.NewRecorder()
	return
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
