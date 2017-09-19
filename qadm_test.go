package pmproxy

import (
	"crypto/rsa"
	"github.com/lamg/errors"
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
	var e *errors.Error
	l, e = ReadAccExcp(sr)
	require.True(t, e == nil)
	var zt time.Time
	zt = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)

	require.True(t, l[0].HostName == "google.com.cu" &&
		l[0].Start == zt && l[0].End == zt && l[0].ConsCfc == 0)
}

func initTestQAdm(c *credentials, ip string) (qa *QAdm,
	s string, e *errors.Error) {
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
		da, jw := newdAuth(), NewJWTCrypt(pKey)
		sm = NewSMng(da, jw)
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
		qa = NewQAdm(sm, gq, uc, l, time.Now(), time.Second)
		s, e = qa.login(c, ip)
	}
	// { qa initialized ∧ c logged in ≡ e = nil }
	return
}

func TestSetQuota(t *testing.T) {
	qa, scrt, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	e = qa.setQuota(pepeIP, scrt, &nameVal{gProf, qProf})
	require.True(t, e == nil)
	e = qa.setQuota(pepeIP, scrt, &nameVal{gEst, qEst})
	require.True(t, e == nil)
}

func TestGetQuota(t *testing.T) {
	var qa *QAdm
	var scrt string
	var e *errors.Error
	qa, scrt, e = initTestQAdm(coco, cocoIP)
	require.True(t, e == nil)
	// { logged in qa }

	v := &nameVal{Name: gProf}
	qa.getQuota(cocoIP, scrt, v)
	require.True(t, v.Value == qProf, "%d≠%d", v.Value, qProf)
	v.Name = gEst
	qa.getQuota(cocoIP, scrt, v)
	require.True(t, v.Value == qEst, "%d≠%d", v.Value, qEst)
}

func TestAddCons(t *testing.T) {
	qa, scrt, e := initTestQAdm(coco, cocoIP)
	require.True(t, e == nil)
	var nc, dwn, n uint64
	dwn = 1024
	nc, e = qa.userCons(cocoIP, scrt, coco.User)
	qa.addCons(cocoIP, dwn)
	n, e = qa.userCons(cocoIP, scrt, coco.User)
	require.True(t, e == nil)
	require.True(t, n == nc+dwn, "%d≠%d", n, nc+dwn)
}

func TestCanReq(t *testing.T) {
	qa, _, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	u, ec := url.Parse("https://14ymedio.com/bla/bla")
	require.NoError(t, ec)
	var c float32
	c = qa.canReq(pepeIP, u, time.Now())
	require.True(t, c == -1, "%.1f ≠ -1", c)
	u, ec = url.Parse("https://google.com.cu/coco/pepe")
	require.NoError(t, ec)
	c = qa.canReq(pepeIP, u, time.Now())
	require.True(t, c == 0, "%.1f ≠ 0", c)
	var fpm time.Time
	fpm, ec = time.Parse(time.RFC3339, "2006-01-02T08:00:01-04:00")
	require.NoError(t, ec)
	u, ec = url.Parse("https://facebook.com/coco")
	require.NoError(t, ec)
	c = qa.canReq(pepeIP, u, fpm)
	require.True(t, c == -1.5, "%.1f ≠ -1.5", c)
	fpm, ec = time.Parse(time.RFC3339, "2006-01-02T08:00:00-04:00")
	require.NoError(t, ec)
	require.False(t, qa.finishedQuota(pepeIP))
	c = qa.canReq(pepeIP, u, fpm)
	require.True(t, c == 1.5, "%.1f ≠ 1.5", c)
}

func TestInDayInterval(t *testing.T) {
	var a, x, y time.Time
	var e error
	a, e = time.Parse(time.RFC3339, "2006-01-02T07:00:00-04:00")
	require.NoError(t, e)
	x, e = time.Parse(time.RFC3339, "2006-01-02T08:00:00-04:00")
	require.NoError(t, e)
	y, e = time.Parse(time.RFC3339, "2006-01-02T14:00:00-04:00")
	require.NoError(t, e)
	var b bool
	b = inDayInterval(a, x, y)
	require.False(t, b)
}

func TestFinishedQuota(t *testing.T) {
	qa, _, e := initTestQAdm(coco, cocoIP)
	require.True(t, e == nil)
	b := qa.finishedQuota(cocoIP)
	require.True(t, b)
	_, e = qa.login(pepe, pepeIP)
	require.True(t, e == nil)
	require.True(t, !qa.finishedQuota(pepeIP))
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
 {"hostName":"14ymedio.com","start":"1959-01-01T00:00:00-04:00","end":"2030-01-01T00:00:00-04:00","consCfc":1},
{"hostName":"facebook.com","daily":true,"start":"2006-01-02T08:00:00-04:00","end":"2006-01-02T14:00:00-04:00","consCfc":1.5}
]`

var cons = `{
 "coco": 8192,
 "pepe": 1024
}`

var quota = `{
 "A": 8192,
 "B": 4096
}`
