package pmproxy

import (
	"github.com/jinzhu/now"
	"github.com/lamg/clock"
	"github.com/lamg/goproxy"
	rs "github.com/lamg/rtimespan"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"testing"
	"time"
)

func TestConnect(t *testing.T) {
	clockDate, actSpanStart := now.MustParse("2006-04-04"),
		now.MustParse("2018-04-04")
	ifs, e := net.Interfaces()
	if e != nil || len(ifs) == 0 {
		panic("Not found interfaces for runnig test")
	}
	cm, dm := NewCMng("cm"),
		&DMng{
			Name: "dm",
			Bandwidth: &Rate{
				Bytes:     1024,
				TimeLapse: time.Millisecond,
			},
		}
	clm, ca := NewCLMng("clm", 100), cm.Adder("coco")
	ts := []tConn{
		{
			addr:    "google.com",
			spec:    new(ConSpec),
			err:     InvCSpecErr(new(ConSpec)),
			content: "GOOGLE",
		},
		{
			addr: "facebook.com",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  ca,
				Proxy: "http://proxy.net",
				Quota: 1024,
				Dm:    dm,
				Span:  nil,
			},
			err: &net.OpError{
				Op:     "dial",
				Net:    "tcp",
				Source: nil,
				Addr:   nil,
				Err:    nil,
			},
		},
		{
			addr: "juju.org",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("pepe"),
				Quota: 2048,
				Dm:    dm,
				Span: &rs.RSpan{
					AllTime: true,
				},
				Test: true,
			},
		},
		{
			addr: "jaja.org",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("kiko"),
				Quota: 4096,
				Dm:    dm,
				Span: &rs.RSpan{
					Start:  actSpanStart,
					Active: time.Hour,
					Total:  24 * time.Hour,
					Times:  1,
				},
				Test: true,
			},
			errRd: TimeOverMsg(clockDate.Add(24*time.Hour),
				clockDate.Add(25*time.Hour)),
		},
		{
			addr: "jeje.org",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("kiko"),
				Quota: 0,
				Dm:    dm,
				Span: &rs.RSpan{
					Start:  actSpanStart,
					Active: time.Hour,
					Total:  24 * time.Hour,
					Times:  1,
				},
				Test: true,
			},
			errRd: DwnOverMsg(),
		},
		{
			addr: "jiji.com",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("cuco"),
				Iface: "eth0",
				Quota: 8192,
				Dm:    dm,
			},
			err: NotIPErr(),
		},
		{
			addr: "jojo.net",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("pepa"),
				Iface: "lo",
				Quota: 1,
				Dm:    dm,
			},
			err: NotFoundIface("lo"),
		},
	}

	cl, dl, p, ifp := &clock.TClock{
		Time: clockDate,
		Intv: time.Minute,
	},
		connDialer(ts),
		goproxy.NewProxyHttpServer(),
		&MIfaceProv{
			Mp: map[string]*net.Interface{
				"eth0": &net.Interface{Name: "eth0"},
			},
		}

	for i, j := range ts {
		c, e := connect(j.addr, j.spec, p, time.Second, cl, dl, ifp)
		ope, ok := e.(*net.OpError)
		if ok {
			ope.Err = nil
			e = ope
		}
		require.Equal(t, j.err, e, "At %d", i)
		if e == nil {
			var bs []byte
			bs, e = ioutil.ReadAll(c)
			require.Equal(t, j.errRd, e)
			require.Equal(t, j.content, string(bs), "At %d", i)
			n := clm.GetAmount(c.LocalAddr().String())
			c.Close()
			m := clm.GetAmount(c.LocalAddr().String())
			require.Equal(t, m+1, n)
		}
	}
}

type tConn struct {
	addr    string
	spec    *ConSpec
	err     error
	errRd   error
	content string
}

func connDialer(ts []tConn) (l Dialer) {
	mp := make(map[string]string)
	for _, j := range ts {
		mp[j.addr] = j.content
	}
	l = &mapDl{
		mc: mp,
	}
	return
}
