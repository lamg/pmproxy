package pmproxy

import (
	rs "github.com/lamg/rtimespan"
	"github.com/stretchr/testify/require"
	"net"
	h "net/http"
	"testing"
	"time"
)

func TestNetC(t *testing.T) {
	tss := []struct {
		cidr []string
		ip   string
		y    bool
	}{
		{[]string{"10.2.1.0/24", "55.2.0.0/16"}, "55.2.0.1", false},
	}
	for i, j := range tss {
		nc := &netC{nt: make([]*net.IPNet, len(j.cidr))}
		for k, l := range j.cidr {
			var e error
			_, nc.nt[k], e = net.ParseCIDR(l)
			require.NoError(t, e)
		}
		nc.ip = net.ParseIP(j.ip)
		require.Equal(t, j.y, nc.V(), "At %d", i)
	}
}

func TestTmC(t *testing.T) {
	tss := []struct {
		start  []string
		active []time.Duration
		total  []time.Duration
		stm    string
		fails  bool
	}{
		{
			start: []string{
				"2018-01-21T00:01:00Z",
				"2018-01-22T00:01:00Z",
			},
			active: []time.Duration{
				time.Hour,
				time.Hour,
			},
			total: []time.Duration{
				24 * time.Hour,
				48 * time.Hour,
			},
			stm:   "2018-01-21T01:00:00Z",
			fails: false,
		},
		{
			start: []string{
				"2018-01-21T00:01:00Z",
				"2018-01-22T00:01:00Z",
			},
			active: []time.Duration{
				time.Hour,
				time.Hour,
			},
			total: []time.Duration{
				24 * time.Hour,
				48 * time.Hour,
			},
			stm:   "2018-01-21T01:50:00Z",
			fails: true,
		},
	}
	for i, j := range tss {
		s := make([]*rs.RSpan, len(j.start))
		for k, l := range j.start {
			t0, e := time.Parse(time.RFC3339, l)
			require.NoError(t, e)
			s[k] = &rs.RSpan{
				Start:    t0,
				Active:   j.active[k],
				Total:    j.total[k],
				Times:    1,
				AllTime:  false,
				Infinite: false,
			}
		}
		tm, e := time.Parse(time.RFC3339, j.stm)
		require.NoError(t, e)
		tmc := &tmC{
			s: s,
			t: tm,
		}
		require.Equal(t, j.fails, tmc.V(), "At %d", i)
	}
}

func TestLdBool(t *testing.T) {
	tl := &tLdFlt{usrs: usrAuthU}
	usrs := append(usrAuthU, admAuthU...)
	ts := make([]struct {
		usr string
		ok  bool
	},
		len(usrs))
	for i, j := range usrs {
		ts[i] = struct {
			usr string
			ok  bool
		}{j, i < len(admAuthU)}
	}
	for i, j := range ts {
		lb := &ldBool{
			usr: j.usr,
			ldf: tl,
			e:   new(err),
		}
		require.NotEqual(t, j.ok, lb.V(), "At %d j.ok: %t", i,
			j.ok)
	}
}

func TestStrSC(t *testing.T) {
	ts := []struct {
		slc []string
		x   string
		ok  bool
	}{
		{
			slc: []string{"a", "b", "c"},
			x:   "a",
			ok:  true,
		}, {
			slc: make([]string, 0),
			x:   "a",
			ok:  true,
		},
		{
			slc: []string{"x", "y", "z"},
			x:   "a",
			ok:  false,
		},
	}
	for i, j := range ts {
		st := &strSC{slc: j.slc, x: j.x}
		require.NotEqual(t, j.ok, st.V(), "At %d", i)
	}
}

func TestEvCond(t *testing.T) {
	cn0 := &Cond{
		CondJ: CondJ{
			ReqPort: []string{"", ":443", ":8080"},
			Usrs:    usrAuthU,
		},
	}
	nw := time.Now()
	e = cn0.InitNets([]string{"55.2.0.0/16", "55.3.67.0/24"})
	require.NoError(t, e)
	ts := []struct {
		ul  string
		t   string
		usr string
	}{
		{
			ul:  "http://google.com",
			t:   nw.Format(time.RFC3339),
			usr: "coco",
		},
	}
}
