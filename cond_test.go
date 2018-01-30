package pmproxy

import (
	rs "github.com/lamg/rtimespan"
	"github.com/stretchr/testify/require"
	"net"
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
				//"2018-01-21T00:01:00Z",
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
