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
	for _, j := range rs {
		bf := bytes.NewBufferString("")
		e := Encode(bf, j)
		require.NoError(t, e)
		r, q := reqres(t, h.MethodPost, "", bf.String(), "", "")
		qc.SrvRes(r, q)
		require.True(t, r.Code == h.StatusOK)
	}
	// check all them are there
	require.Equal(t, len(rs), len(qc.Rm.rs))
	// replace all
	rpl := make([]*Res, 10)
	for i := range rpl {
		rpl[i] = &Res{
			Cn: &Cond{
				Usrs: usrAuthU,
			},
			InD: UsrDet(""),
		}
		// TODO stackoverflow, I think because Idet isn't
		// properly defined for serialization
		bf := bytes.NewBufferString("")
		e := Encode(bf, rpl[i])
		require.NoError(t, e)
		println(bf.String())
		r, q := reqres(t,
			h.MethodPut, fmt.Sprintf("/?index=%d", i),
			bf.String(), "", "")

		qc.SrvRes(r, q)
		println("ko")
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
}
