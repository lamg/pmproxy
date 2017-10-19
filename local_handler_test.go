package pmproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
	"net"
	. "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	// ErrorServeHTTP is the error when a response of the server
	// has a code different from 200
	ErrorServeHTTP = iota
)

func initPMProxy() (p *PMProxy, e *errors.Error) {
	qa, rl, e := initQARL()
	if e == nil {
		p = NewPMProxy(qa, rl,
			map[string]string{"B": "eth0", "A": "eth1"})
	}
	return
}

func TestServerLogInOut(t *testing.T) {
	qa, _, e := initQARL()
	require.True(t, e == nil)
	pm := NewLocalHn(qa, "")
	require.True(t, e == nil)
	rr, rq := reqres(t, MethodPost, LogX,
		`{"user":"a", "pass":"a"}`, cocoIP)
	pm.ServeHTTP(rr, rq)
	require.Equal(t, rr.Code, StatusOK)
	u, e := NewUserFR(rr.Body)
	require.True(t, e == nil)
	e = pm.qa.sm.check(cocoIP, u)
	require.True(t, e == nil)
	require.True(t, u.UserName == "a" &&
		pm.qa.sm.User(cocoIP).Equal(u))

	usr, _ := u.ToJSON()
	rr, rq = reqres(t, MethodDelete, LogX, usr, cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK, "Code: %d", rr.Code)
	require.True(t, pm.qa.sm.User(cocoIP) == nil, "%v ≠ nil",
		pm.qa.sm.User(cocoIP))

	testUnsMeth(t, pm, LogX, MethodConnect)
}

func loginServ(t *testing.T) (lh *LocalHn, s string) {
	qa, _, e := initQARL()
	require.True(t, e == nil)
	lh = NewLocalHn(qa, "")
	rr, rq := reqres(t, MethodPost, LogX,
		`{"user":"coco", "pass":"coco"}`, cocoIP)
	lh.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusOK)
	s = rr.Body.String()
	return
}

func TestGetUserStatus(t *testing.T) {
	pm, u := loginServ(t)
	rr, rq := reqres(t, MethodPost, UserStatus, u, cocoIP)
	pm.ServeHTTP(rr, rq)
	us := new(QtCs)
	ec := json.Unmarshal(rr.Body.Bytes(), us)
	require.NoError(t, ec)
	cv, ok := pm.qa.uc.Load(coco.User)
	require.True(t, ok)
	require.True(t, us.Consumption == cv)
	usr, e := NewUserFR(strings.NewReader(u))
	require.True(t, e == nil)
	e = pm.qa.sm.check(cocoIP, usr)
	require.True(t, e == nil)
	qv, ok := pm.qa.gq.Load(usr.QuotaGroup)
	require.True(t, ok)
	require.True(t, us.Quota == qv)
	testUnsMeth(t, pm, UserStatus, MethodConnect)
}

func TestPutUserStatus(t *testing.T) {
	pm, s := loginServ(t)
	v, ok := pm.qa.uc.Load(coco.User)
	require.True(t, ok)
	require.True(t, v > 0)
	r, q := reqres(t, MethodPut, UserStatus,
		fmt.Sprintf(
			`{"user":%s,"userName":"coco","consumption":0}`, s),
		cocoIP)
	pm.ServeHTTP(r, q)
	require.True(t, r.Code == StatusOK, "Code: %d Body:%s",
		r.Code, r.Body.String())
	v, ok = pm.qa.uc.Load(coco.User)
	require.True(t, ok)
	require.True(t, v == 0, "v = %d ≠ 0", v)
}

func TestCode(t *testing.T) {
	bf := bytes.NewBufferString("")
	e := Encode(bf, make(chan int, 0))
	require.True(t, e != nil && e.Code == ErrorEncode)
	e = Decode(bf, 0)
	require.True(t, e != nil && e.Code == ErrorDecode)
}

func setQV(u *url.URL, k, v string) {
	vs := u.Query()
	vs.Set(k, v)
	u.RawQuery = vs.Encode()
}

func testUnsMeth(t *testing.T, pm *LocalHn, path, meth string) {
	rr := httptest.NewRecorder()
	rq, ec := NewRequest(meth, path, nil)
	require.NoError(t, ec)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == StatusBadRequest)
}

func reqres(t *testing.T, meth, path, body,
	addr string) (r *httptest.ResponseRecorder, q *Request) {
	var e error
	if body != "" {
		by := bytes.NewBufferString(body)
		q, e = NewRequest(meth, path, by)
	} else {
		q, e = NewRequest(meth, path, nil)
	}
	require.NoError(t, e)
	q.Host = net.JoinHostPort(q.Host, "443")
	q.RemoteAddr = net.JoinHostPort(addr, "443")
	r = httptest.NewRecorder()
	return
}
