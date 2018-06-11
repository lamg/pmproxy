package pmproxy

import (
	rg "regexp"
	"strings"
	"testing"
	"time"

	"github.com/lamg/clock"

	"github.com/stretchr/testify/require"
)

func TestLoadAccStr(t *testing.T) {
	var sr *strings.Reader
	sr = strings.NewReader(accR)
	var l []AccExcp
	var e error
	l, e = ReadAccExcp(sr)
	require.True(t, e == nil)
	tss := []AccExcp{
		{
			rg.MustCompile("google\\.com\\.cu$"),
			false,
			time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
			0,
		},
		{
			rg.MustCompile("14ymedio\\.com$"),
			false,
			time.Date(1959, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			1,
		},
		{
			rg.MustCompile("facebook\\.com$"),
			true,
			time.Date(2006, 1, 2, 8, 0, 0, 0, time.UTC),
			time.Date(2006, 1, 2, 14, 0, 0, 0, time.UTC),
			1.5,
		},
	}

	for i, j := range tss {
		b0 := j.HostR.String() == l[i].HostR.String()
		require.True(t, b0, "Test %s ≠ %s",
			j.HostR.String(), l[i].HostR.String())
		b1 := j.Daily == l[i].Daily
		require.True(t, b1, "%t ≠ %t", j.Daily, l[i].Daily)
		b2 := j.Start.Equal(l[i].Start)
		require.True(t, b2, "%s ≠ %s",
			j.Start.String(), l[i].Start.String())
		b3 := j.End.Equal(l[i].End)
		require.True(t, b3, "%s ≠ %s", j.End, l[i].End)
		b4 := j.ConsCfc == l[i].ConsCfc
		require.True(t, b4, "%.1f ≠ %.1d",
			j.ConsCfc, l[i].ConsCfc)
	}
}

func initTestQAdm(c *credentials, ip string) (qa *QAdm,
	s string, e error) {
	qa, _, e = initQARL(tClock())
	var lr *LogRs
	if e == nil {
		lr, e = qa.login(c, ip)
	}
	if e == nil {
		s = lr.Scrt
	}
	// { qa initialized ∧ c logged in ≡ e = nil }
	return
}

func TestSetCons(t *testing.T) {
	qa, scrt, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	tss := []NameVal{
		NameVal{"a", qProf},
		NameVal{pepe.User, qEst},
	}
	for _, j := range tss {
		e = qa.setCons(pepeIP, scrt, &j)
		require.True(t, e == nil)
		v, ok := qa.uc.Load(j.Name)
		require.True(t, ok)
		require.True(t, v == j.Value)
	}
}

func TestGetQuota(t *testing.T) {
	qa, scrt, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	// { logged in qa }
	v, e := qa.getQuota(pepeIP, scrt)
	require.True(t, e == nil)
	require.True(t, v == qProf, "%d≠%d", v, qProf)
	cuco, cucoIP := "cuco", "3.3.3.3"
	var lr *LogRs
	lr, e = qa.login(&credentials{User: cuco, Pass: cuco},
		cucoIP)
	require.Nil(t, e)
	v, e = qa.getQuota(cucoIP, lr.Scrt)
	require.Equal(t, uint64(qEst+qProf), v)
	// { since cuco is in group A and also B
	// then its quota is A's quota + B's quota}
}

func TestAddCons(t *testing.T) {
	qa, s, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	tss := []struct {
		ip   string
		host string
		dwn  int
		hd   string
	}{
		{pepeIP, "cubadebate.cu", 1024, s},
	}
	for _, j := range tss {
		nc, e := qa.userCons(j.ip, j.hd)
		require.True(t, e == nil)
		qa.cons(j.ip, j.host, j.dwn)
		n, e := qa.userCons(j.ip, j.hd)
		require.True(t, e == nil)
		ac := nc + uint64(j.dwn)
		require.True(t, n == ac, "%d≠%d", n, ac)
	}
}

func TestCanReq(t *testing.T) {
	qa, _, e := initTestQAdm(pepe, pepeIP)
	qa.login(coco, cocoIP)
	stl := []string{
		"2006-01-02T08:00:01-04:00",
		"2006-01-02T08:00:01-04:00",
		"2006-01-02T08:00:01-04:00",
		"2006-01-02T08:00:00-04:00",
		"2006-01-02T08:00:00-04:00",
		"2006-01-02T08:00:00-04:00",
		"2006-01-02T08:00:00-04:00",
		"2006-01-02T08:00:00-04:00",
	}
	ts := make([]time.Time, len(stl))
	for i, j := range stl {
		var ec error
		ts[i], ec = time.Parse(time.RFC3339, j)
		require.NoError(t, ec)
	}
	qa.cl = clock.NewTLClock(ts)
	require.True(t, e == nil)
	cases := []struct {
		host string
		port string
		ip   string
		k    float32
	}{
		{"14ymedio.com", "443", cocoIP, -1},
		{"google.com.cu", "443", cocoIP, 0},
		{"facebook.com", "443", pepeIP, -1.5},
		{"facebook.com", "443", pepeIP, 1.5},
		{"detectportal.firefox.com", "", cocoIP, 0},
		{"debian.org", "80", pepeIP, 1},
		{"news.ycombinator.com", "443", pepeIP, 1},
		{"news.ycombinator.com", "441", pepeIP, -1},
	}
	for i, j := range cases {
		c, cs := qa.canReq(j.ip, j.host, j.port)
		require.True(t, c == j.k, "%.1f ≠ %.1f at %d", c, j.k, i)
		require.True(t, c != 0 || cs == nil, "At %d", i)
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
	qa, _, e := initTestQAdm(pepe, pepeIP)
	require.True(t, e == nil)
	tss := []struct {
		ip     string
		logged bool
	}{
		{cocoIP, false},
		{pepeIP, true},
	}
	for i, j := range tss {
		b := qa.isLogged(j.ip)
		require.True(t, j.logged == b, "At %d %t ≠ %t",
			i, j.logged, b)
	}
}

const (
	gProf = "A"
	gEst  = "B"
	qProf = 8192
	qEst  = 4096
	adr0  = "0.0.0.0"
)
