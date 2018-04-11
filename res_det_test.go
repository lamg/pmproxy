package pmproxy

import (
	"github.com/stretchr/testify/require"
	"net"
	h "net/http"
	"regexp"
	"testing"
	"time"
)

func TestDet(t *testing.T) {
	_, rg, e := net.ParseCIDR("10.1.1.0/24")
	require.NoError(t, e)
	sd := &SqDet{
		Unit: true,
		Ds: []Det{
			&ResDet{
				Rg: rg,
			},
			&ResDet{
				Ur: regexp.MustCompile("facebook.com"),
				Pr: &ConSpec{
					Cf: 0,
				},
			},
		},
	}
	_, q := reqres(t, h.MethodGet, "https://facebook.com", "", "",
		"10.1.1.34")
	c := new(ConSpec)
	sd.Det(q, time.Now(), c)
	require.Equal(t, float32(0), c.Cf)
}
