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

func TestQAdm(t *testing.T) {
	qa := new(QAdm)

	// init of l
	var sr *strings.Reader
	sr = strings.NewReader(accR)
	var l []AccExcp
	var e error
	l, e = ReadAccExcp(sr)
	require.NoError(t, e)

	// init of sm
	sm, dAuth, cry := new(SMng), new(dAuth), new(JWTCrypt)
	dAuth.Init()

	var pKey *rsa.PrivateKey
	pKey, e = parseKey()
	require.NoError(t, e)
	cry.Init(pKey)
	sm.Init(dAuth, cry)

	// init of gq
	sgq := &stringCloser{strings.NewReader(quota)}
	gq := NewMapPrs(sgq, NewDWF(), time.Now(), time.Second)

	// init of uc
	suc := &stringCloser{strings.NewReader(cons)}
	uc := NewMapPrs(suc, NewDWF(), time.Now(), time.Second)

	qa.Init(sm, gq, uc, l, time.Now(), time.Second)
	qa.SetQuota(pepeIP, gProf, &NameVal{pepe.User, qProf})
	qa.SetQuota(cocoIP, gEst, &NameVal{coco.User, qEst})
	var n uint64
	var ok bool
	n, ok = qa.gq.Load(gProf)
	require.True(t, ok && n == qProf)
	n, ok = qa.gq.Load(gEst)
	require.True(t, ok && n == qEst)
	var scrt string
	scrt, e = qa.Login(coco, adr0)
	require.NoError(t, e)
	qa.AddCons(adr0, 1024)
	usr := &User{Name: coco.User}
	n, e = qa.UserCons(cocoIP, scrt, usr.Name)
	require.NoError(t, e)
	require.True(t, n == 4096)
	gqt := &NameVal{Name: gProf}
	qa.GetQuota(cocoIP, scrt, gqt)
	require.True(t, gqt.Value == qProf)
	gqt = &NameVal{Name: gEst}
	qa.GetQuota(cocoIP, scrt, gqt)
	require.True(t, gqt.Value == qEst)
	var u *url.URL
	u, e = url.Parse("https://14ymedio.com/bla/bla")
	require.NoError(t, e)
	var c float64
	c = qa.CanReq(adr0, u, time.Now())
	require.True(t, c == -1)
	qa.Logout(cocoIP, scrt)
	gqt.Value = 0
	qa.GetQuota(cocoIP, scrt, gqt)
	require.True(t, gqt.Value == 0)
}

const (
	gProf = "UPR-Internet-Estudiantes"
	gEst  = "UPR-Internet-Profesores"
	qProf = 8192
	qEst  = 16384
	adr0  = "0.0.0.0"
)

type stringCloser struct {
	*strings.Reader
}

func (b *stringCloser) Close() (e error) {
	return
}

var accR = `[
 {"hostName":"google.com.cu","start":"","end":"",consCfc:0},
 {"hostName":"14ymedio.com","start":"","end":"",consCfc:-1},
]`

var cons = `{
 "coco": 8192,
 "pepe": 1024,
}`

var quota = `{
 "UPR-Internet-Estudiantes": 4096,
 "UPR-Internet-Profesores": 8192,
}`
