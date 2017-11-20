package pmproxy

import (
	"bytes"
	"encoding/json"
	"net"
	h "net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
)

const (
	// ErrorServeHTTP is the error when a response of the server
	// has a code different from 200
	ErrorServeHTTP = iota
)

func initPMProxy() (p *PMProxy, e *errors.Error) {
	qa, rl, e := initQARL()
	if e == nil {
		rmng := NewRRConnMng(nil, qa, rl,
			map[string]string{"B": "eth0", "A": "eth1"},
			map[string]float64{
				"A": 0.9,
				"B": 0.8,
			},
		)
		p = NewPMProxy(rmng, new(url.URL))
	}
	return
}

func TestServerLogInOut(t *testing.T) {
	qa, _, e := initQARL()
	require.True(t, e == nil)
	pm := NewLocalHn(qa, "")
	require.True(t, e == nil)
	tss := []struct {
		method    string
		route     string
		body      string
		ip        string
		emptyScrt bool
	}{
		{h.MethodPost, LogX, `{"user":"a", "pass":"a"}`, cocoIP,
			false},
		{h.MethodDelete, LogX, "", cocoIP, true},
	}
	var hd string
	for i, j := range tss {
		rr, rq := reqres(t, j.method, j.route, j.body, hd, j.ip)
		pm.ServeHTTP(rr, rq)
		require.Equal(t, rr.Code, h.StatusOK, "%d: Code = %d", i,
			rr.Code)
		require.True(t, (rr.Body.Len() == 0) == j.emptyScrt)
		if !j.emptyScrt {
			// { this is a login and not a logout }
			lg := new(LogRs)
			e = Decode(rr.Body, lg)
			require.True(t, e == nil)
			hd = lg.Scrt
		}
	}
}

func TestGetUserStatus(t *testing.T) {
	tss := []struct {
		c  *credentials
		ip string
	}{
		{coco, cocoIP},
		{pepe, pepeIP},
	}
	for _, j := range tss {
		pm, hd := loginServ(t, j.c, j.ip)
		cv, ok := pm.qa.uc.Load(j.c.User)
		require.True(t, ok)
		usr, e := pm.qa.sm.userInfo(j.ip, hd)
		require.True(t, e == nil)
		qv, ok := pm.qa.gq.Load(usr.QuotaGroup)
		require.True(t, ok)
		// { cv and qv are the consumption and quota of j.c }
		rr, rq := reqres(t, h.MethodGet, UserStatus, "", hd, j.ip)
		pm.ServeHTTP(rr, rq)
		us := new(QtCs)
		ec := json.Unmarshal(rr.Body.Bytes(), us)
		require.NoError(t, ec)
		// { us is the QtCs object returned by the server }
		require.True(t, us.Consumption == cv)
		require.True(t, us.Quota == qv)
	}
}

func TestPutUserStatus(t *testing.T) {
	tss := []struct {
		c  *credentials
		ip string
		cs uint64
	}{
		{coco, cocoIP, 0},
	}
	for _, j := range tss {
		pm, s := loginServ(t, j.c, j.ip)
		nv := &NameVal{j.c.User, j.cs}
		bs, ec := json.Marshal(nv)
		require.NoError(t, ec)
		r, q := reqres(t, h.MethodPut, UserStatus, string(bs),
			s, j.ip)
		pm.ServeHTTP(r, q)
		require.True(t, r.Code == h.StatusOK, "Code: %d Body:%s",
			r.Code, r.Body.String())
		// { the request to set the consumption of j.c is sent}
		v, ok := pm.qa.uc.Load(j.c.User)
		require.True(t, ok)
		require.True(t, v == j.cs, "v = %d ≠ %d", v, j.cs)
		// { the consumption obtained from the consumptions
		//  dictionary directly, is equal to the sent as request
		//  to set}
	}
}

func TestCheckUserHF(t *testing.T) {
	tss := []struct {
		c     *credentials
		ip    string
		rCode int
	}{
		{coco, cocoIP, h.StatusOK},
	}
	for _, j := range tss {
		pm, hd := loginServ(t, j.c, j.ip)
		r, q := reqres(t, h.MethodGet, CheckUser, "", hd, j.ip)
		pm.ServeHTTP(r, q)
		require.True(t, r.Code == j.rCode)
	}
}

func TestUserInfoHF(t *testing.T) {
	tss := []struct {
		c     *credentials
		ip    string
		rCode int
		u     *User
	}{
		{coco, cocoIP, h.StatusOK, &User{UserName: coco.User}},
	}
	for _, j := range tss {
		pm, hd := loginServ(t, j.c, j.ip)
		r, q := reqres(t, h.MethodGet, UserInfo, "", hd, j.ip)
		pm.ServeHTTP(r, q)
		require.True(t, r.Code == j.rCode)
		u := new(User)
		e := Decode(r.Body, u)
		require.True(t, e == nil)
		require.True(t, u.UserName == j.u.UserName)
	}
}

func TestCode(t *testing.T) {
	bf := bytes.NewBufferString("")
	e := Encode(bf, make(chan int, 0))
	require.True(t, e != nil && e.Code == ErrorEncode)
	e = Decode(bf, 0)
	require.True(t, e != nil && e.Code == ErrorDecode)
}

func TestUnsMethod(t *testing.T) {
	pm, hd := loginServ(t, coco, cocoIP)
	tss := []struct {
		path string
		meth string
		scrt string
	}{
		{LogX, h.MethodConnect, ""},
		{UserStatus, h.MethodConnect, hd},
		{UserInfo, h.MethodConnect, hd},
	}
	for _, j := range tss {
		r, q := reqres(t, j.meth, j.path, "", j.scrt, cocoIP)
		pm.ServeHTTP(r, q)
		require.True(t, r.Code == h.StatusBadRequest)
	}
}

func loginServ(t *testing.T, c *credentials, ip string) (lh *LocalHn, s string) {
	qa, _, e := initQARL()
	require.True(t, e == nil)

	lh = NewLocalHn(qa, "")
	bs, ec := json.Marshal(c)
	require.NoError(t, ec)
	rr, rq := reqres(t, h.MethodPost, LogX, string(bs), "", ip)
	lh.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusOK)
	lr := new(LogRs)
	e = Decode(rr.Body, lr)
	require.True(t, e == nil)
	s = lr.Scrt
	// { user c is logged from ip }
	return
}

func setQV(u *url.URL, k, v string) {
	vs := u.Query()
	vs.Set(k, v)
	u.RawQuery = vs.Encode()
}

func reqres(t *testing.T, meth, path, body, hd,
	addr string) (r *httptest.ResponseRecorder, q *h.Request) {
	var e error
	if body != "" {
		by := bytes.NewBufferString(body)
		q, e = h.NewRequest(meth, path, by)
	} else {
		q, e = h.NewRequest(meth, path, nil)
	}
	require.NoError(t, e)
	q.Host = net.JoinHostPort(q.Host, "443")
	q.RemoteAddr = net.JoinHostPort(addr, "443")
	q.Header.Set(AuthHd, hd)
	r = httptest.NewRecorder()
	return
}
