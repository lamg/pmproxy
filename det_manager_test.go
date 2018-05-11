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
	}
	for i, j := range ts {
		bs, e := json.Marshal(j.dt)
		require.NoError(t, e)
		indS := fmt.Sprintf("/index/%d", j.ind)
		w, r := reqres(t, h.MethodPost, indS, string(bs), "", "0.0.0.0")
		_, ok := j.dt.(*SqDet)
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
		require.Equal(t, bs, dbs, "At %d", i)
	}
}
