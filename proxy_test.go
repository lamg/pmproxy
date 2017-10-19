package pmproxy

import (
	"bytes"
	"crypto/rsa"
	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	h "net/http"
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
		da, cry := NewDAuth(), NewJWTCrypt(pKey)
		sm = NewSMng(da, cry)
	}

	var gq *QuotaMap
	if e == nil {
		gqp := NewPersister(w.NewDWF(), time.Now(), time.Second)
		gq, e = NewQMFromR(bytes.NewBufferString(quota), gqp)
	}

	var uc *ConsMap
	if e == nil {
		ucp := NewPersister(w.NewDWF(), time.Now(), time.Second)
		uc, e = NewCMFromR(bytes.NewBufferString(cons), ucp)
	}
	qa = NewQAdm(sm, gq, uc, l)
	// rl initialization
	rl = NewRLog(w.NewDWF(), sm)
	return
}

func TestLocalRequest(t *testing.T) {
	rr, rq := reqres(t, h.MethodGet, "/", "", cocoIP)
	pm, e := initPMProxy()
	require.True(t, e == nil)
	pm.ServeHTTP(rr, rq)
	rs := rr.Result()
	require.True(t, rs.StatusCode == h.StatusNotFound,
		"Status = %d", rs.StatusCode)

	rr, rq = reqres(t, h.MethodPost, UserStatus, "", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusNotFound,
		"Status = %d", rr.Code)
}

func TestForbiddenReq(t *testing.T) {
	pm, e := initPMProxy()
	require.True(t, e == nil)
	rr, rq := reqres(t, h.MethodGet, "https://twitter.com",
		"", cocoIP)
	pm.ServeHTTP(rr, rq)
	require.True(t, rr.Code == h.StatusForbidden &&
		rr.Body.String() == "No tiene acceso",
		"Code: %d", rr.Code)
}

func TestGetUsrNtIf(t *testing.T) {
	pm, e := initPMProxy()
	require.True(t, e == nil)
	var u *User
	u, e = pm.qa.login(pepe, pepeIP)
	require.True(t, e == nil)
	var s string
	s, e = u.ToJSON()
	require.True(t, e == nil)
	_, rq := reqres(t, h.MethodGet, "https://twitter.com",
		s, pepeIP)
	n, ec := pm.getUsrNtIf(rq)
	require.True(t, ec == nil)
	require.True(t, n == "eth1")
}
