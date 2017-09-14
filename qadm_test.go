package pmproxy

import (
	"crypto/rsa"
	. "github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoadAccStr(t *testing.T) {
	var sr *strings.Reader
	sr = strings.NewReader(accR)
	var l []AccExcp
	var e error
	l, e = ReadAccExcp(sr)
	require.NoError(t, e)
	var zt time.Time
	zt = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)

	require.True(t, l[0].HostName == "google.com.cu" &&
		l[0].Start == zt && l[0].End == zt && l[0].ConsCfc == 0)
}

func initTestQAdm(c *Credentials, ip string) (qa *QAdm,
	s string, e error) {
	var sr *strings.Reader
	sr = strings.NewReader(accR)
	var l []AccExcp
	l, e = ReadAccExcp(sr)
	// { l initialized ≡ e = nil }
	var pKey *rsa.PrivateKey
	if e == nil {
		pKey, e = parseKey()
	}
	var sm *SMng
	if e == nil {
		var da *dAuth
		var jw *JWTCrypt
		sm, da, jw = new(SMng), new(dAuth), new(JWTCrypt)
		da.Init()
		jw.Init(pKey)
		sm.Init(da, jw)
	}
	// { sm initialized ≡ e = nil}

	var gq *MapPrs
	if e == nil {
		sgq := &stringCloser{strings.NewReader(quota)}
		gq, e = NewMapPrs(sgq, NewDWF(), time.Now(), time.Second)
	}
	// { gq initialized ≡ e = nil }
	var uc *MapPrs
	if e == nil {
		suc := &stringCloser{strings.NewReader(cons)}
		uc, e = NewMapPrs(suc, NewDWF(), time.Now(), time.Second)
	}
	// { uc initialized ≡ e = nil }
	if e == nil {
		qa = new(QAdm)
		qa.Init(sm, gq, uc, l, time.Now(), time.Second)
		s, e = qa.Login(c, ip)
	}
	// { qa initialized ∧ c logged in ≡ e = nil }
	return
}

func TestSetQuota(t *testing.T) {
	var qa *QAdm
	var scrt string
	var e error
	qa, scrt, e = initTestQAdm(pepe, pepeIP)
	require.NoError(t, e)
	e = qa.SetQuota(pepeIP, scrt, &NameVal{gProf, qProf})
	require.NoError(t, e)
	e = qa.SetQuota(pepeIP, scrt, &NameVal{gEst, qEst})
	require.NoError(t, e)
}

func TestGetQuota(t *testing.T) {
	var qa *QAdm
	var scrt string
	var e error
	qa, scrt, e = initTestQAdm(coco, cocoIP)
	require.NoError(t, e)
	// { logged in qa }

	v := &NameVal{Name: gProf}
	qa.GetQuota(cocoIP, scrt, v)
	require.True(t, v.Value == qProf, "%d≠%d", v.Value, qProf)
	v.Name = gEst
	qa.GetQuota(cocoIP, scrt, v)
	require.True(t, v.Value == qEst, "%d≠%d", v.Value, qEst)
}

func TestAddCons(t *testing.T) {
	var qa *QAdm
	var scrt string
	var e error
	qa, scrt, e = initTestQAdm(coco, cocoIP)
	require.NoError(t, e)
	var nc, dwn, n uint64
	dwn = 1024
	nc, e = qa.UserCons(cocoIP, scrt, coco.User)
	qa.AddCons(cocoIP, dwn)
	n, e = qa.UserCons(cocoIP, scrt, coco.User)
	require.NoError(t, e)
	require.True(t, n == nc+dwn, "%d≠%d", n, nc+dwn)
}

func TestCanReq(t *testing.T) {
	var qa *QAdm
	var e error
	qa, _, e = initTestQAdm(coco, cocoIP)
	require.NoError(t, e)
	var u *url.URL
	u, e = url.Parse("https://14ymedio.com/bla/bla")
	require.NoError(t, e)
	var c float32
	c = qa.CanReq(cocoIP, u, time.Now())
	require.True(t, c == -1, "%.1f ≠ -1", c)
	u, e = url.Parse("https://google.com.cu/coco/pepe")
	require.NoError(t, e)
	c = qa.CanReq(cocoIP, u, time.Now())
	require.True(t, c == 0, "%.1f ≠ 0", c)
}

const (
	gProf = "A"
	gEst  = "B"
	qProf = 8192
	qEst  = 4096
	adr0  = "0.0.0.0"
)

type stringCloser struct {
	*strings.Reader
}

func (b *stringCloser) Close() (e error) {
	return
}

var accR = `[
 {"hostName":"google.com.cu","start":null,"end":null,"consCfc":0},
 {"hostName":"14ymedio.com","start":null,"end":null,"consCfc":-1}
]`

var cons = `{
 "coco": 8192,
 "pepe": 1024
}`

var quota = `{
 "A": 8192,
 "B": 4096
}`
