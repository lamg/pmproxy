package pmproxy

import (
	"github.com/jinzhu/now"
	"github.com/stretchr/testify/require"
	"net"
	h "net/http"
	"regexp"
	"testing"
	"time"
)

func TestDet(t *testing.T) {
	// TODO test determinators deeply
	now.TimeFormats = append(now.TimeFormats, time.RFC3339)
	ts := []struct {
		ip  string
		url string
		tm  string
		dt  Det
		ok  bool
		c   *ConSpec
	}{
		{
			ip:  "10.1.1.24",
			url: "https://facebook.com",
			tm:  "2018-04-12T00:00:00-04:00",
			dt: &SqDet{
				Unit: true,
				Ds: []Det{
					&ResDet{
						Unit: true,
						Rg:   parseRange(t, "10.1.1.0/24"),
						// there's no need to specify Cf here
					},
					&ResDet{
						Unit: true,
						Ur:   regexp.MustCompile("facebook.com"),
						Pr: &ConSpec{
							Cf: 1,
						},
					},
				},
			},
			ok: true,
			c:  &ConSpec{Cf: 1},
		},
	}

	for i, j := range ts {
		_, q := reqres(t, h.MethodGet, j.url, "", "", j.ip)
		c, m := new(ConSpec), now.MustParse(j.tm)
		ok := j.dt.Det(q, m, c)
		require.Equal(t, j.ok, ok, "At %d", i)
		require.Equal(t, j.c, c, "At %d", i)
	}
}

func parseRange(t *testing.T, cidr string) (n *net.IPNet) {
	var e error
	_, n, e = net.ParseCIDR(cidr)
	require.NoError(t, e)
	return
}
