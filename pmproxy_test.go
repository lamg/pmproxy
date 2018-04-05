package pmproxy

import (
	"bytes"
	"fmt"
	"github.com/jinzhu/now"
	"github.com/lamg/clock"
	gp "github.com/lamg/goproxy"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	h "net/http"
	"sync"
	"testing"
	"time"
)

func TestDial(t *testing.T) {
	d := &testGen{
		addrContent: map[string]string{
			"172.93.101.12": "GOOGLE",
			"143.33.24.8":   "FACEBOOK",
		},
		loggedAddr: []string{"0.0.0.0", "0.0.0.1"},
	}
	ts, rd, dl := d.genTestStructs(), d.genDet(), d.genDialer()
	cl := &clock.TClock{
		Intv: time.Second,
		Time: now.MustParse("2018-01-01"),
	}
	pm := NewPMProxy(rd, cl, dl, time.Second)
	for i, j := range ts {
		ctx := &gp.ProxyCtx{
			Req: j.request,
		}
		c, e := pm.Dial("", j.request.URL.Hostname(), ctx)
		require.True(t, (e == nil) == j.ok, "At %d", i)
		if e == nil {
			s, e := ioutil.ReadAll(c)
			require.NoError(t, e)
			require.Equal(t, j.content, s)
		}
	}
}

type testGen struct {
	addrContent map[string]string
	loggedAddr  []string
}

func (d *testGen) genTestStructs() (ts []testS) {
	ts, i := make([]testS, len(d.addrContent)), 0
	for k, v := range d.addrContent {
		req, e := h.NewRequest(h.MethodGet, "http://"+k, nil)
		if e != nil {
			panic(e.Error)
		}
		ts[i], i = testS{
			request: req,
			content: v,
			ok:      true,
		},
			i+1
	}
	return
}

func (d *testGen) genDet() (rd []Det) {
	sm, cl := NewSMng("sm", nil, nil), &CLMng{Limit: 100, Name: "cl"}
	dm := &DMng{
		Bandwidth: &Rate{
			Bytes:     1024,
			TimeLapse: time.Millisecond,
		},
		Name: "dm",
		Sm:   sm,
	}
	for _, j := range d.loggedAddr {
		sm.login("user", j)
	}
	cm := &CMng{
		Cons: new(sync.Map),
		Name: "cm",
		Sm:   sm,
	}
	rd = []Det{
		&ResDet{
			Um: &UsrMtch{
				Sm: sm,
			},
			Pr: &ConSpec{
				Cf:    0,
				Cl:    cl,
				Cons:  cm,
				Iface: "eth0",
				Quota: 1024,
				Rt:    dm.NewConnRate(),
			},
		},
	}
	return
}

func (d *testGen) genDialer() (l Dialer) {
	l = &mapDl{
		mc: d.addrContent,
	}
	return
}

type mapDl struct {
	mc map[string]string
}

func (m *mapDl) Dial(l *net.TCPAddr, t time.Duration,
	addr string) (c net.Conn, e error) {
	s, ok := m.mc[addr]
	ip := net.ParseIP(addr)
	if ok && ip != nil {
		r := &net.TCPAddr{
			IP: ip,
		}
		c = &bfConn{
			Buffer: bytes.NewBufferString(s),
			local:  l,
			remote: r,
		}
	} else {
		e = fmt.Errorf("Not found key %s", addr)
	}
	return
}

type bfConn struct {
	local  *net.TCPAddr
	remote *net.TCPAddr
	*bytes.Buffer
}

func (b *bfConn) Close() (e error) {
	return
}

func (b *bfConn) LocalAddr() (r net.Addr) {
	r = b.local
	return
}

func (b *bfConn) RemoteAddr() (r net.Addr) {
	r = b.remote
	return
}

func (b *bfConn) SetDeadline(t time.Time) (e error) {

	return
}

func (b *bfConn) SetReadDeadline(t time.Time) (e error) {
	return
}

func (b *bfConn) SetWriteDeadline(t time.Time) (e error) {
	return
}

type testS struct {
	content string
	request *h.Request
	ok      bool
}
