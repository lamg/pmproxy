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
	tss := []struct {
		meth string
		path string
		ip   string
	}{
		{h.MethodGet, "/", cocoIP},
		{h.MethodGet, UserStatus, pepeIP},
	}
	for _, j := range tss {
		pm, e := initPMProxy()
		require.True(t, e == nil)
		rr, rq := reqres(t, j.meth, j.path, "", "", j.ip)
		pm.ServeHTTP(rr, rq)
		require.True(t, rr.Code == h.StatusNotFound,
			"Status = %d", rr.Code)
	}
}

func TestReq(t *testing.T) {
	tss := []struct {
		meth string
		url  string
		ip   string
		code int
		body string
	}{
		{h.MethodGet, "https://twitter.com", cocoIP,
			h.StatusForbidden, "No tiene acceso"},
	}
	for _, j := range tss {
		pm, e := initPMProxy()
		require.True(t, e == nil)
		rr, rq := reqres(t, h.MethodGet, j.url, "", "", j.ip)
		pm.ServeHTTP(rr, rq)
		require.True(t, rr.Code == j.code &&
			rr.Body.String() == j.body, "Code: %d", rr.Code)
	}
}

func TestGetUsrNtIf(t *testing.T) {
	tss := []struct {
		c     *credentials
		ip    string
		url   string
		iface string
	}{
		{pepe, pepeIP, "https://twitter.com", "eth1"},
		{coco, cocoIP, "https://google.com.cu", "eth1"},
	}
	for _, j := range tss {
		pm, e := initPMProxy()
		require.True(t, e == nil)
		var lr *LogRs
		lr, e = pm.qa.login(j.c, j.ip)
		require.True(t, e == nil)
		_, rq := reqres(t, h.MethodGet, j.url, "", lr.Scrt, j.ip)
		n, ec := pm.getUsrNtIf(rq)
		require.True(t, ec == nil)
		require.True(t, n == j.iface)
	}
}
