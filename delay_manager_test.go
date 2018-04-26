package pmproxy

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
	"time"
)

func TestServeInfo(t *testing.T) {
	sm := NewSMng("sm", nil, nil)
	loggedAddr := "0.0.0.1"
	sm.login("coco", loggedAddr)
	dm := &DMng{
		Name: "dm",
		Bandwidth: &Rate{
			Bytes:     1024,
			TimeLapse: time.Millisecond,
		},
		Sm: sm,
	}
	ca := uint64(100)
	for i := uint64(0); i != ca; i++ {
		rt := dm.IncConn()
		w, r := reqres(t, h.MethodGet, "", "", "", loggedAddr)
		dm.ServeInfo(w, r)
		require.Equal(t, h.StatusOK, w.Code)
		di := new(dInfo)
		e := Decode(w.Body, di)
		require.NoError(t, e)
		require.Equal(t, dm.Bandwidth, di.Bandwidth)
		require.Equal(t, rt, di.ConnR)
		require.Equal(t, i+1, di.CurrConn)
	}
}

func TestServeSetBW(t *testing.T) {
	sm := NewSMng("sm", nil, nil)
	loggedAddr := "0.0.0.1"
	sm.login("coco", loggedAddr)
	dm := &DMng{
		Name: "dm",
		Bandwidth: &Rate{
			Bytes:     1024,
			TimeLapse: time.Millisecond,
		},
		Sm: sm,
	}
	nbw := &Rate{
		Bytes:     2048,
		TimeLapse: time.Nanosecond,
	}
	bs, e := json.Marshal(nbw)
	require.NoError(t, e)
	w, r := reqres(t, h.MethodPut, "", string(bs), "", loggedAddr)
	dm.ServeSetBW(w, r)
	w0, r0 := reqres(t, h.MethodGet, "", "", "", loggedAddr)
	dm.ServeInfo(w0, r0)
	require.Equal(t, h.StatusOK, w.Code)
	di := new(dInfo)
	e = Decode(w0.Body, di)
	require.NoError(t, e)
	require.Equal(t, nbw, di.Bandwidth)
}
