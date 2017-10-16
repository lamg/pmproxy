package pmproxy

import (
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
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
	qa, _, e = initQARL()
	if e == nil {
		s, e = qa.login(c, ip)
	}
	// { qa initialized ∧ c logged in ≡ e = nil }
	return
}

func TestSetCons(t *testing.T) {
	qa, scrt, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	e = qa.setCons(pepeIP, scrt, &nameVal{gProf, qProf})
	require.True(t, e == nil)
	e = qa.setCons(pepeIP, scrt, &nameVal{gEst, qEst})
	require.True(t, e == nil)
}

func TestGetQuota(t *testing.T) {
	var qa *QAdm
	var scrt string
	var e *errors.Error
	qa, scrt, e = initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	// { logged in qa }

	var v uint64
	v, e = qa.getQuota(pepeIP, scrt)
	require.True(t, v == qProf, "%d≠%d", v, qProf)
}

func TestAddCons(t *testing.T) {
	qa, scrt, e := initTestQAdm(coco, cocoIP)
	require.True(t, e == nil)
	var nc, dwn, n uint64
	nc, e = qa.userCons(cocoIP, scrt)
	require.True(t, e == nil)
	dwn = 1024
	qa.addCons(cocoIP, dwn)
	n, e = qa.userCons(cocoIP, scrt)
	require.True(t, e == nil)
	require.True(t, n == nc+dwn, "%d≠%d", n, nc+dwn)
}

func TestCanReq(t *testing.T) {
	qa, _, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	cases := []struct {
		host string
		port string
		tm   string
		ip   string
		k    float32
	}{
		{"14ymedio.com", "443",
			"2006-01-02T08:00:01-04:00", cocoIP, -1},
		{"google.com.cu", "443",
			"2006-01-02T08:00:01-04:00", cocoIP, 0},
		{"facebook.com", "443",
			"2006-01-02T08:00:01-04:00", pepeIP, -1.5},
		{"facebook.com", "443",
			"2006-01-02T08:00:00-04:00", pepeIP, 1.5},
		{"debian.org", "80", "2006-01-02T08:00:00-04:00",
			pepeIP, 1},
		{"news.ycombinator.com", "443",
			"2006-01-02T08:00:00-04:00", pepeIP, 1},
		{"news.ycombinator.com", "441",
			"2006-01-02T08:00:00-04:00", pepeIP, -1},
	}
	for i, j := range cases {
		tm, e := time.Parse(time.RFC3339, j.tm)
		require.True(t, e == nil, "Time at %d", i)
		c := qa.canReq(j.ip, j.host, j.port, tm)
		require.True(t, c == j.k, "%.1f ≠ %.1f at %d", c, j.k, i)
	}
}

func TestInDayInterval(t *testing.T) {
	i, ts, s := 0, make([]time.Time, 3), []string{
		"2006-01-02T07:00:00-04:00",
		"2006-01-02T08:00:00-04:00",
		"2006-01-02T14:00:00-04:00",
	}
	var e error
	for i != len(s) && e == nil {
		ts[i], e = time.Parse(time.RFC3339, s[i])
		i = i + 1
	}
	require.NoError(t, e)
	b := inDayInterval(ts[0], ts[1], ts[2])
	require.False(t, b)
}

func TestNlf(t *testing.T) {
	qa, _, e := initTestQAdm(coco, cocoIP)
	require.True(t, e == nil)
	b := qa.nlf(cocoIP)
	require.True(t, b)
	_, e = qa.login(pepe, pepeIP)
	require.True(t, e == nil)
	require.True(t, !qa.nlf(pepeIP))
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
	"lastReset":"2017-10-02T14:00:00-04:00",
	"resetTime":1000000000,
	"userCons":{
 		"coco": 8192,
 		"pepe": 1024
	}
}`

var quota = `{
 "A": 8192,
 "B": 4096
}`
