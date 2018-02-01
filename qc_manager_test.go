package pmproxy

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	h "net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestSrvRes(t *testing.T) {
	qc := &QCMng{
		Rm: &RdMng{
			rs: make([]*Res, 0),
		},
		Cons: new(sync.Map),
	}
	rs := make([]*Res, 10)
	for i := range rs {
		rs[i] = new(Res)
	}
	// post a few
	for i, j := range rs {
		bf := bytes.NewBufferString("")
		e := Encode(bf, j)
		require.NoError(t, e)
		r, q := reqres(t, h.MethodPost, "", bf.String(), "", "")
		qc.SrvRes(r, q)
		require.True(t, r.Code == h.StatusOK)
		require.Equal(t, i+1, len(qc.Rm.rs))
	}
	// check all them are there
	for i := 0; i != len(qc.Rm.rs)+1; i++ {
		r, q := reqres(t, h.MethodGet,
			fmt.Sprintf("/?index=%d", i), "", "", "")
		qc.SrvRes(r, q)
		if i == len(qc.Rm.rs) {
			require.Equal(t, IndexOutOfRange().Error(), r.Body.String())
			require.Equal(t, h.StatusBadRequest, r.Code)
		} else {
			grs := new(Res)
			require.Equal(t, h.StatusOK, r.Code, "At %d", i)
			e := Decode(r.Body, &grs)
			require.NoError(t, e)
		}
	}
	// replace all
	rpl := make([]*Res, 10)
	for i := range rpl {
		rpl[i] = &Res{
			Cn: &Cond{
				CondJ: CondJ{Usrs: usrAuthU},
			},
			InD: &Idet{Sel: "user"},
		}
		bf := bytes.NewBufferString("")
		e := Encode(bf, rpl[i])
		require.NoError(t, e)
		r, q := reqres(t,
			h.MethodPut, fmt.Sprintf("/?index=%d", i),
			bf.String(), "", "")
		qc.SrvRes(r, q)
		require.Equal(t, h.StatusOK, r.Code)
	}
	// check all were replaced
	for i, j := range qc.Rm.rs {
		require.Equal(t, rpl[i].Cn.Usrs, j.Cn.Usrs)
	}
	// delete them
	for i := 0; i != len(rs); i++ {
		r, q := reqres(t, h.MethodDelete, "/?index=0", "", "", "")
		qc.SrvRes(r, q)
		require.Equal(t, h.StatusOK, r.Code)
	}
	// check none are there
	require.Equal(t, 0, len(qc.Rm.rs))
	// check invalid url produces index out of range
	r, q := reqres(t, h.MethodDelete, "", "", "", "")
	qc.SrvRes(r, q)
	require.Equal(t, h.StatusBadRequest, r.Code)
	require.Equal(t, IndexOutOfRange().Error(), r.Body.String())
}

func TestSrvCs(t *testing.T) {
	qc := &QCMng{
		Cons: new(sync.Map),
	}
	l, cns, dwn := uint32(10), uint32(10), uint64(256)
	// fill qc.Cons with some user-*Cons pairs
	for i := uint32(0); i != l; i++ {
		qc.Cons.Store(fmt.Sprint(i), &Cons{
			Cns: cns + i,
			Dwn: dwn + uint64(i),
		})
	}
	// check all them are there
	for i := uint32(0); i != l; i++ {
		w, r := reqres(t, h.MethodGet,
			fmt.Sprintf("/?key=%d", i), "", "", "")
		qc.SrvCs(w, r)
		require.Equal(t, h.StatusOK, w.Code)
		cs := new(Cons)
		e := Decode(w.Body, cs)
		require.NoError(t, e)
		require.Equal(t, cns+i, cs.Cns)
		require.Equal(t, dwn+uint64(i), cs.Dwn)
	}
	// replace all of them
	for i := uint32(0); i != l; i++ {
		bf, cs := bytes.NewBufferString(""), &Cons{
			Cns: cns * i,
			Dwn: dwn * uint64(i),
		}
		e := Encode(bf, cs)
		require.NoError(t, e)
		w, r := reqres(t, h.MethodPut,
			fmt.Sprintf("/?key=%d", i), bf.String(), "", "")
		qc.SrvCs(w, r)
		require.Equal(t, h.StatusOK, w.Code)
	}
	// check all them are there
	for i := uint32(0); i != l; i++ {
		w, r := reqres(t, h.MethodGet,
			fmt.Sprintf("/?key=%d", i), "", "", "")
		qc.SrvCs(w, r)
		require.Equal(t, h.StatusOK, w.Code)
		cs := new(Cons)
		e := Decode(w.Body, cs)
		require.NoError(t, e)
		require.Equal(t, cns*i, cs.Cns)
		require.Equal(t, dwn*uint64(i), cs.Dwn)
	}
	// delete all of them
	for i := uint32(0); i != l; i++ {
		w, r := reqres(t, h.MethodDelete,
			fmt.Sprintf("/?key=%d", i), "", "", "")
		qc.SrvCs(w, r)
		require.Equal(t, h.StatusOK, w.Code)
	}
	// check none are there
	cont := 0
	qc.Cons.Range(func(k, v interface{}) (b bool) {
		b, cont = true, cont+1
		return
	})
	require.Equal(t, 0, cont)
}

func TestServeHTTPQCMng(t *testing.T) {
	// TODO
	// initialize QCMng
	prx0url := "http://proxy.goo.com:8080"
	prx0, e := url.Parse(prx0url)
	require.NoError(t, e)
	trec, tcl := new(tQtCsRec), &tClock{tm: time.Now()}
	qt0 := &Quota{
		QuotaJ: QuotaJ{
			Dwn:   1024,
			Iface: "eth0",
			MCn:   256,
			Proxy: prx0url,
		},
		proxy: prx0,
	}
	cn0 := &Cond{
		CondJ: CondJ{
			ReqPort: []string{"", ":443", ":8080"},
			Usrs:    usrAuthU,
		},
	}
	e = cn0.InitNets([]string{"55.2.0.0/16", "55.3.67.0/24"})
	require.NoError(t, e)
	tldf := &tLdFlt{usrs: usrAuthU}
	qc := &QCMng{
		Cl: tcl,
		Qr: trec,
		Rm: &RdMng{
			rs: []*Res{
				&Res{
					Cn: cn0,
					InD: &Idet{
						Sel: "user",
					},
					Qt: qt0,
				},
			},
			LdF: tldf,
		},
		Cons: new(sync.Map),
	}
	// check rules work
	trs := []struct {
		url  string
		user string
		addr string
		qc   *QtCs
	}{
		{"https://google.com.cu", "coco", "0.0.0.0", nil},
		{"https://google.com.cu", "coco", "55.2.0.1",
			&QtCs{Qt: qt0},
		},
	}
	for i, j := range trs {
		// make requests
		w, r := reqres(t, h.MethodGet, j.url, "", "", j.addr)
		qc.Rec(j.user)
		qc.ServeHTTP(w, r)
		// check state is OK
		if j.qc == nil {
			require.Equal(t,
				NoResourceMsg(r, tcl.Now(), j.user).Error(),
				w.Body.String())
		} else {
			require.False(t, qc.V(), "At %d", i)
			require.Equal(t, j.qc.Qt.Dwn, trec.qc.Qt.Dwn)
			require.Equal(t, j.qc.Qt.Iface, trec.qc.Qt.Iface)
			require.Equal(t, j.qc.Qt.MCn, trec.qc.Qt.MCn)
			require.Equal(t, j.qc.Qt.Proxy, trec.qc.Qt.Proxy)
			require.Equal(t, j.qc.Qt.Span.Start,
				trec.qc.Qt.Span.Start)
			require.Equal(t, j.qc.Qt.Thr, trec.qc.Qt.Thr)
		}
	}
}

type tLdFlt struct {
	usrs []string
}

func (l *tLdFlt) UserOK(usr string) (ok bool, e error) {
	ok = false
	for i := 0; !ok && i != len(l.usrs); i++ {
		ok = l.usrs[i] == usr
	}
	return
}

type tQtCsRec struct {
	qc *QtCs
}

func (r *tQtCsRec) Rec(qc *QtCs) {
	r.qc = qc
	return
}

type tClock struct {
	tm time.Time
}

func (c *tClock) Now() (t time.Time) {
	t = c.tm
	return
}
