package pmproxy

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
)

func TestSrvDet(t *testing.T) {
	// create
	d := &DetMng{
		MainDet: &SqDet{
			Unit: false,
		},
		Router: mux.NewRouter(),
	}
	ua := &Auth{
		Um: usrAuthM,
	}
	ts := []struct {
		dt  Det
		ind uint32
		add bool
	}{
		{
			dt: &SqDet{
				Unit: false,
				Ds: []Det{
					&ResDet{
						Unit: true,
						Cs:   NewCMng("cm"),
					},
				},
			},
			ind: 0,
			add: true,
		},
		{
			dt: &ResDet{
				Um: &UsrMtch{
					Sm: NewSMng("sm", ua, nil),
				},
			},
			ind: 1,
			add: true,
		},
	}
	for i, j := range ts {
		bs, e := json.Marshal(j.dt)
		require.NoError(t, e)
		w, r := reqres(t, h.MethodPost, "/", string(bs), "", "0.0.0.0")
		d.SrvAddDet(w, r)
		require.Equal(t, h.StatusOK, w.Code, "At %d", i)
		dtbs, e := detIndexBFSBytes(d.MainDet, j.ind)
		require.NoError(t, e)
		require.Equal(t, bs, dtbs, "At %d", i)
	}
}

func detIndexBFSBytes(s *SqDet, n uint32) (bs []byte, e error) {
	ds, i := []Det{s}, uint32(0)
	for i != n && len(ds) != 0 {
		v := ds[0]
		h, ok := v.(*SqDet)
		if ok {
			ds = append(ds[1:], h.Ds...)
		}
		i = i + 1
	}
	if len(ds) != 0 {
		bs, e = json.Marshal(ds[0])
	}
	return
}
