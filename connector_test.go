package pmproxy

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	h "net/http"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/jinzhu/now"
	"github.com/lamg/clock"
	"github.com/lamg/proxy"
	rs "github.com/lamg/rtimespan"
	"github.com/stretchr/testify/require"
)

func testCMng() (cm *CMng) {
	clockDate := now.MustParse("2006-04-04")
	cl := &clock.TClock{
		Time: clockDate,
		Intv: time.Minute,
	}
	cm = &CMng{
		Name:       "cm",
		Cl:         cl,
		ResetCycle: time.Hour,
		LastReset:  clockDate,
		Cons:       new(sync.Map),
	}
	return
}

type tConn struct {
	addr    string
	spec    *ConSpec
	err     error
	errRd   error
	content string
}

func TestConnect(t *testing.T) {
	clockDate, actSpanStart := now.MustParse("2006-04-04"),
		now.MustParse("2018-04-04")
	cl := &clock.TClock{
		Time: clockDate,
		Intv: time.Minute,
	}
	n := &Connector{
		Cl: cl,
		Dl: &TestDialer{
			Mp: map[string]map[string]string{
				"eth0": map[string]string{
					"google.com": "GOOGLE",
					"jiji.com":   "",
					"juju.org":   "",
					"jaja.org":   "",
					"jeje.org":   "",
				},
			},
		},
	}
	cm, dm := testCMng(),
		&DMng{
			Name: "dm",
			Bandwidth: &Rate{
				Bytes:     1024,
				TimeLapse: time.Millisecond,
			},
		}
	clm := NewCLMng("clm", 100)
	ts := []tConn{
		{
			addr:    "google.com",
			spec:    new(ConSpec),
			err:     InvCSpec(new(ConSpec)),
			content: "GOOGLE",
		},
		{
			addr: "juju.org",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("pepe"),
				Iface: "eth0",
				Quota: 2048,
				Dm:    dm,
				Span: &rs.RSpan{
					AllTime: true,
				},
			},
		},
		{
			addr: "jaja.org",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("kiko"),
				Iface: "eth0",
				Quota: 4096,
				Dm:    dm,
				Span: &rs.RSpan{
					Start:  actSpanStart,
					Active: time.Hour,
					Total:  24 * time.Hour,
					Times:  1,
				},
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
				Iface: "eth0",
				Quota: 0,
				Dm:    dm,
				Span: &rs.RSpan{
					Start:  actSpanStart,
					Active: time.Hour,
					Total:  24 * time.Hour,
					Times:  1,
				},
			},
			errRd: DwnOverMsg(),
		},
		{
			addr: "koko.com",
			spec: &ConSpec{
				Cf:    1,
				Cl:    clm,
				Cons:  cm.Adder("cuco"),
				Iface: "eth0",
				Quota: 8192,
				Dm:    dm,
			},
			err: NotFoundAddr("koko.com"),
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

	for i, j := range ts {
		c, e := n.connect(j.addr, j.spec)
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
			// connection content is ok

			n := clm.Amount(c.LocalAddr().String())
			c.Close()
			m := clm.Amount(c.LocalAddr().String())
			require.Equal(t, m+1, n)
			// connection limit manager works
		}
	}
}

func TestProxy(t *testing.T) {
	n := &Connector{
		Rd: &SqDet{
			RDs: []*ResDet{
				&ResDet{
					Ur: regexp.MustCompile("bla\\.com"),
					Pr: &ConSpec{
						Proxy: "http://proxy.org",
					},
				},
			},
		},
		Cl: &clock.TClock{
			Time: now.MustParse("2006-04-01"),
			Intv: time.Minute,
		},
	}
	ts := []string{
		"bla.com",
	}
	for i, j := range ts {
		r, e := h.NewRequest(h.MethodGet, j, nil)
		require.NoError(t, e, "At %d", i)
		var u *url.URL
		u, e = n.Proxy(r)
		require.NoError(t, e, "At %d", i)
		require.NotNil(t, u, "At %d", i)
	}
}

func TestDialContext(t *testing.T) {
	n, _, e := testConnector(nil)
	require.NoError(t, e)
	ts := []tConn{
		{
			addr:    "bla.com",
			content: "BLABLA",
		},
	}
	for i, j := range ts {
		r, e := h.NewRequest(h.MethodGet, j.addr, nil)
		require.NoError(t, e, "At %d", i)
		r.RemoteAddr = "0.0.0.0" + ":3433"
		ctx := context.WithValue(context.Background(), proxy.ReqKey, r)
		var c net.Conn
		c, e = n.DialContext(ctx, "tcp", j.addr)
		require.NoError(t, e, "At %d", i)
		var bs []byte
		bs, e = ioutil.ReadAll(c)
		require.NoError(t, e, "At %d", i)
		require.Equal(t, j.content, string(bs))
	}
}

func TestLoggingDial(t *testing.T) {
	chk := &checker{
		inputs:  []string{"1143864060.000 5000000 0.0.0.0 TCP_MISS/200 0 GET bla.com keke DIRECT/- -\n"},
		current: 0,
	}
	lg := log.New(chk, "", 0)
	n, ts, e := testConnector(lg)
	require.NoError(t, e)
	for i, j := range ts {
		_, e = n.DialContext(j.ctx, "tcp", j.addr)
		require.NoError(t, e, "At %d", i)
		require.NoError(t, chk.err, "At %d", i)
	}
}

func testConnector(lg *log.Logger) (n *Connector, ts []tConn0, e error) {
	cm, dm, sm := testCMng(),
		&DMng{
			Name: "dm",
			Bandwidth: &Rate{
				Bytes:     1024,
				TimeLapse: time.Millisecond,
			},
		},
		NewSMng("sm", nil, nil)
	keke, kekeIP := "keke", "0.0.0.0"
	sm.login(keke, kekeIP)
	n = &Connector{
		Lg: lg,
		Rd: &SqDet{
			RDs: []*ResDet{
				&ResDet{
					Unit: true,
					Ur:   regexp.MustCompile("bla\\.com"),
					Pr: &ConSpec{
						Cf:    1,
						Iface: "eth0",
						Quota: 4096,
						Cons:  cm.Adder("keke"),
					},
					Dm: dm,
					Cs: cm,
					Um: &UsrMtch{
						Sm: sm,
					},
				},
			},
		},
		Cl: &clock.TClock{
			Time: now.MustParse("2006-04-01"),
			Intv: time.Minute,
		},
		Dl: &TestDialer{
			Mp: map[string]map[string]string{
				"eth0": map[string]string{
					"bla.com": "BLABLA",
				},
			},
		},
	}
	ts, e = newTConns([]string{"bla.com"}, []string{"0.0.0.0"})
	return
}

func newTConns(hosts, remotes []string) (ts []tConn0, e error) {
	// len(hosts) = len(remotes) = len(ts)
	ts = make([]tConn0, len(hosts))
	for i := 0; e == nil && i != len(hosts); i++ {
		var r *h.Request
		r, e = h.NewRequest(h.MethodGet, hosts[i], nil)
		r.RemoteAddr = remotes[i] + ":3234"
		ts[i] = tConn0{
			ctx: context.WithValue(context.Background(), proxy.ReqKey,
				r),
			addr: hosts[i],
		}
	}
	return
}

type tConn0 struct {
	ctx  context.Context
	addr string
}

type checker struct {
	inputs  []string
	current uint32
	err     error
}

func (c *checker) Write(bs []byte) (n int, e error) {
	s := string(bs)
	if c.current < uint32(len(c.inputs)) {
		t := c.inputs[c.current]
		if t != s {
			e = fmt.Errorf("%s != %s", s, t)
		}
	} else {
		e = fmt.Errorf("All %d checked", len(c.inputs))
	}
	c.current = c.current + 1
	c.err = e
	return
}
