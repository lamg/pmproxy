package pmproxy

import (
	"bytes"
	"crypto/rsa"
	h "net/http"
	"testing"
	"time"

	"github.com/lamg/clock"

	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
)

func initQARL(cl clock.Clock) (qa *QAdm, rl *RLog, e *errors.Error) {
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
		cl = &clock.TClock{Intv: time.Second, Time: dtTime()}
		gqp := NewPersister(w.NewDWF(), dtTime(), time.Second,
			cl)
		gq, e = NewQMFromR(bytes.NewBufferString(quota), gqp)
	}

	var uc *ConsMap
	if e == nil {
		ucp := NewPersister(w.NewDWF(), dtTime(), time.Second,
			cl)
		uc, e = NewCMFromR(bytes.NewBufferString(cons), ucp)
	}
	qa = NewQAdm(sm, gq, uc, l, cl)
	// rl initialization
	rl = NewRLog(w.NewDWF(), sm)
	return
}

func dtTime() (dt time.Time) {
	var e error
	dt, e = time.Parse(time.RFC3339,
		"2017-10-03T14:00:00-04:00")
	if e != nil {
		panic(e.Error())
	}
	return
}

func TestLocalRequest(t *testing.T) {
	tss := []struct {
		meth string
		path string
		ip   string
		c    *credentials
		code int
	}{
		{h.MethodGet, "/", cocoIP, nil, h.StatusTemporaryRedirect},
		{h.MethodGet, UserStatus, pepeIP, nil,
			h.StatusTemporaryRedirect},
		{h.MethodGet, "/", cocoIP, coco, h.StatusTemporaryRedirect},
		{h.MethodGet, UserStatus, pepeIP, pepe, h.StatusNotFound},
		{h.MethodGet, "https://twitter.com", cocoIP, nil,
			h.StatusTemporaryRedirect},
	}
	for i, j := range tss {
		pm, e := initPMProxy()
		require.True(t, e == nil)
		rr, rq := reqres(t, j.meth, j.path, "", "", j.ip)
		if j.c != nil {
			pm.rmng.qa.login(j.c, j.ip)
		}
		pm.ServeHTTP(rr, rq)
		require.True(t, rr.Code == j.code,
			"%d != %d at %d", rr.Code, j.code, i)
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
		lr, e = pm.rmng.qa.login(j.c, j.ip)
		require.True(t, e == nil)
		_, rq := reqres(t, h.MethodGet, j.url, "", lr.Scrt, j.ip)
		n, ec := pm.rmng.getUsrNtIf(rq.RemoteAddr)
		require.True(t, ec == nil)
		require.True(t, n == j.iface)
	}
}
