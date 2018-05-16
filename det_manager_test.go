package pmproxy

import (
	"encoding/json"
	"fmt"
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
				RDs: []*ResDet{
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
		{
			dt: &SqDet{
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Dm: &DMng{
							Name: "dm",
						},
					},
				},
			},
			ind: 1,
			add: true,
		},
	}
	for i, j := range ts {
		bs, e := json.Marshal(j.dt)
		require.NoError(t, e)
		_, ok := j.dt.(*SqDet)
		w, r := reqres(t, h.MethodPost, "/"+Index, string(bs), "",
			"0.0.0.0")
		r = mux.SetURLVars(r, map[string]string{
			Index: fmt.Sprint(j.ind),
		})
		if ok {
			d.SrvAddSqDet(w, r)
		} else {
			d.SrvAddResDet(w, r)
		}
		require.Equal(t, h.StatusOK, w.Code, "At %d", i)
		sq := detIndexBFS(d.MainDet, j.ind)
		var dbs []byte
		if ok {
			dbs, e = json.Marshal(sq.SDs[len(sq.SDs)-1])
		} else {
			dbs, e = json.Marshal(sq.RDs[len(sq.RDs)-1])
		}
		require.NoError(t, e)
		require.Equal(t, string(bs), string(dbs), "At %d", i)
	}

	// DetMng.SrvDet test
	w, r := reqres(t, h.MethodGet, "/"+Index, "", "", "")
	r = mux.SetURLVars(r, map[string]string{
		Index: "2",
	})
	d.SrvDet(w, r)
	require.Equal(t, h.StatusOK, w.Code)
	bs, e := json.Marshal(ts[2].dt)
	require.NoError(t, e)
	require.Equal(t, string(bs), w.Body.String())

}
