package pmproxy

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	h "net/http"
	"sync"
	"testing"
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
	// TODO
}
