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
	cl, ifp := &clock.TClock{
		Intv: time.Second,
		Time: now.MustParse("2018-01-01"),
	},
		new(OSIfProv)

	pm := NewPMProxy(rd, cl, dl, time.Second, ifp) //root
	for i, j := range ts {
		ctx := &gp.ProxyCtx{
			Req: j.request,
		}
		c, e := pm.Dial("", j.request.URL.Hostname(), ctx)
		require.True(t, (e == nil) == j.ok, "At %d", i)
		if e == nil {
			s, e := ioutil.ReadAll(c)
			require.NoError(t, e)

			require.Equal(t, j.content, string(s)) //root
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
		req.RemoteAddr = d.loggedAddr[i] + ":4432"
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
	sm, cl := NewSMng("sm", nil, nil), NewCLMng("cl", 100)
	dm := &DMng{
		Bandwidth: &Rate{
			Bytes:     1024,
			TimeLapse: time.Millisecond,
		},
		Name: "dm",
		Sm:   sm,
	}
	for i, j := range d.loggedAddr {
		usr := fmt.Sprintf("user%d", i)
		sm.login(usr, j)
	}
	cm := &CMng{
		Cons: new(sync.Map),
		Name: "cm",
	}
	ifs, e := net.Interfaces()
	if e != nil || len(ifs) == 0 {
		panic("Not found interfaces for runnig test")
	}
	rd = []Det{
		&ResDet{
			Um: &UsrMtch{
				Sm: sm,
			},
			Unit: true,
			Cs:   cm,
			Dm:   dm,
			Pr: &ConSpec{
				Cf:    0,
				Cl:    cl,
				Iface: ifs[0].Name,
				Quota: 1024,
				Dm:    dm,
			},
		},
	}
	// currently rd just let the connection pass through
	// for logged users
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
		e = notFoundAddr(addr)
	}
	return
}

func notFoundAddr(addr string) (e error) {
	e = fmt.Errorf("Not found address %s", addr)
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
