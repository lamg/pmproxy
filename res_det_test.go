package pmproxy

import (
	"encoding/json"
	"net"
	h "net/http"
	"regexp"
	"testing"
	"time"

	"github.com/jinzhu/now"
	rs "github.com/lamg/rtimespan"
	"github.com/stretchr/testify/require"
)

type testReq struct {
	ip  string
	url string
	tm  string
	ok  bool
	c   *ConSpec
}

func TestSeqDetTrue(t *testing.T) {
	now.TimeFormats = append(now.TimeFormats, time.RFC3339)
	sq := &SqDet{
		Unit: true,
		RDs: []*ResDet{
			&ResDet{
				Unit: true,
				Rg:   parseRange(t, "10.1.1.0/24"),
				// there's no need to specify Cf here
			},
			&ResDet{
				Unit: true,
				Rs: &rs.RSpan{
					Start:  now.MustParse("2018-04-11T23:59:59-04:00"),
					Active: 10 * time.Minute,
					Total:  time.Hour,
					Times:  1,
				},
			},
			&ResDet{
				Unit: true,
				Ur:   regexp.MustCompile("facebook.com"),
				Pr: &ConSpec{
					Cf: 1,
				},
			},
		},
	}

	ts := []testReq{
		{
			ip:  "10.1.1.24",
			url: "https://facebook.com",
			tm:  "2018-04-12T00:00:00-04:00",
			ok:  true,
			c:   &ConSpec{Cf: 1},
		},
		{
			ip:  "10.1.1.24",
			url: "https://facebook.com",
			tm:  "2018-04-13T00:00:00-04:00",
			ok:  false,
			c:   new(ConSpec),
		},
	}
	testSeq(t, ts, sq)
}

func TestSeqDetFalse(t *testing.T) {
	now.TimeFormats = append(now.TimeFormats, time.RFC3339)
	sq := &SqDet{
		Unit: false,
		SDs: []*SqDet{
			&SqDet{
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Ur:   regexp.MustCompile("^nomatch\\.com$"),
					},
				},
			},
			&SqDet{
				Unit: false,
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Rg:   parseRange(t, "10.1.1.0/24"),
						// there's no need to specify Cf here
						Pr: &ConSpec{
							Cf: 3,
						},
					},
					&ResDet{
						Unit: true,
						Ur:   regexp.MustCompile("^facebook\\.com$"),
						Pr: &ConSpec{
							Cf:    1,
							Proxy: "http://proxy.cu:8080",
						},
					},
				},
			},
		},
	}
	ts := []testReq{
		{
			ip:  "10.2.1.24",
			url: "https://facebook.com",
			tm:  "2018-04-12T00:00:00-04:00",
			ok:  true,
			c: &ConSpec{
				Cf:    1,
				Proxy: "http://proxy.cu:8080",
			},
		},
		{
			ip:  "10.1.1.24",
			url: "https://google.com",
			tm:  "2018-04-12T00:00:00-04:00",
			ok:  true,
			c:   &ConSpec{Cf: 3},
		},
	}
	testSeq(t, ts, sq)
}

func testSeq(t *testing.T, ts []testReq, sq Det) {
	for i, j := range ts {
		_, q := reqres(t, h.MethodGet, j.url, "", "", j.ip)
		c, m := new(ConSpec), now.MustParse(j.tm)
		ok := sq.Det(q, m, c)
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

func TestMarshalJSON(t *testing.T) {
	rs := []*ResDet{
		&ResDet{
			Unit: true,
			Rg:   parseRange(t, "10.1.1.0/24"),
			// there's no need to specify Cf here
			Pr: &ConSpec{
				Cf: 3,
			},
			Dm: &DMng{
				Name: "dm",
			},
			Cs: NewCMng("cs"),
		},
		&ResDet{
			Unit: true,
			Ur:   regexp.MustCompile("facebook.com"),
			Pr: &ConSpec{
				Cf:    1,
				Proxy: "http://proxy.cu:8080",
			},
			Cl: NewCLMng("cl", 0),
		},
	}
	bs, e := json.Marshal(rs)
	require.NoError(t, e)
	rd := make([]*ResDet, 0)
	json.Unmarshal(bs, &rd)
	for i, j := range rs {
		require.Equal(t, j.Unit, rd[i].Unit, "At %d")
		if j.Rg != nil {
			require.Equal(t, j.Rg.String(), rd[i].Rg.String(), "At %d")
		}
		if j.Dm != nil {
			require.Equal(t, j.Dm.Name, rd[i].Dm.Name, "At %d")
		}
		if j.Cs != nil {
			require.Equal(t, j.Cs.Name, rd[i].Cs.Name, "At %d")
		}
		if j.Ur != nil {
			require.Equal(t, j.Ur.String(), rd[i].Ur.String(), "At %d")
		}
		if j.Cl != nil {
			require.Equal(t, j.Cl.Name, rd[i].Cl.Name, "At %d")
		}
	}
}
