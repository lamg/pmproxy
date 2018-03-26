package pmproxy

import (
	"bytes"
	"github.com/jinzhu/now"
	"github.com/lamg/clock"
	gp "github.com/lamg/goproxy"
	"github.com/stretchr/testify/require"
	"net"
	h "net/http"
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
	ts, rd, dl := d.getTestStructs(), d.genDet(), d.genDialer()
	cl := clock.TLClock{
		Interval: time.Second,
		Time:     now.MustParse("2018-01-01"),
	}
	pm := NewPMProxy(rd, cl, dl, time.Second)
	for i, j := range ts {
		ctx := &gp.ProxyCtx{
			Req: j.request,
		}
		c, e = pm.Dial("", j.request.URL.Host(), ctx)
		require.True(t, (e == nil) == j.ok)
		if e == nil {
			s, e := ioutil.ReadAll(c)
			require.NoError(t, e)
			require.Equal(t, ts.content, s)
		}
	}
}

type testGen struct {
	addrContent map[string]string
	loggedAddr  []string
}

func (d *testGen) genTestStructs() (ts []testS) {
	ts = make([]testS, len(d.addrContent))
	for k, v := range d.addrContent {
		req, e := h.NewRequest(h.MethodGet, "http://"+k, nil)
		if e != nil {
			panic(e.Error)
		}
		ts[i] = testS{
			request: req,
			content: v,
			ok:      true,
		}
	}
	return
}

func (d *testGen) genDet() (rd []Det) {
	sm := NewSMng("sm", nil, nil)
	for _, j := range d.loggedAddr {
		sm.login("user", j)
	}
	rd = []Det{
		&UsrMtch{
			Sm: sm,
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
	ip, e := net.ParseIP(addr)
	if ok && e == nil {
		r := net.TCPAddr{
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
