package pmproxy

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestSrvDet(t *testing.T) {
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
		err bool
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
			ind: 18,
			add: true,
			err: true,
		},
		{
			dt: &ResDet{
				Um: &UsrMtch{
					Sm: NewSMng("sm", ua, nil),
				},
			},
			ind: 18,
			add: true,
			err: true,
		},
	}
	for i, j := range ts {
		sq0, ok := j.dt.(*SqDet)
		bs, e := json.Marshal(j.dt)
		require.NoError(t, e)

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
		if !j.err {
			require.Equal(t, h.StatusOK, w.Code, "At %d", i)
			sq := detIndexPreorder(d.MainDet, j.ind)
			if ok {
				v0, v1 := toJSqDet(sq0), toJSqDet(sq.SDs[len(sq.SDs)-1])
				require.Equal(t, v0, v1, "At %d", i)
			} else {
				var dbs []byte
				dbs, e = json.Marshal(sq.RDs[len(sq.RDs)-1])
				require.NoError(t, e)
				require.Equal(t, string(bs), string(dbs), "At %d", i)
			}
		} else {
			require.Equal(t, h.StatusBadRequest, w.Code, "At %d", i)
			require.Equal(t, NoDetFound().Error(), w.Body.String(),
				"At %d", i)
		}
	}

	// DetMng.SrvDet test
	tsd := []struct {
		index string
		err   bool
	}{
		{
			index: "2",
		},
		{
			index: "18",
			err:   true,
		},
	}
	for i, j := range tsd {
		w, r := reqres(t, h.MethodGet, "/"+Index, "", "", "")
		r = mux.SetURLVars(r, map[string]string{
			Index: j.index,
		})
		d.SrvDet(w, r)
		if !j.err {
			require.Equal(t, h.StatusOK, w.Code)
			sq, ok := ts[2].dt.(*SqDet)
			require.True(t, ok)
			v := toJSqDet(sq)
			bs, e := json.Marshal(v)
			require.NoError(t, e)
			require.Equal(t, string(bs), w.Body.String(), "At %d", i)
		} else {
			require.Equal(t, h.StatusBadRequest, w.Code, "At %d", i)
			require.Equal(t, NoDetFound().Error(), w.Body.String(),
				"At %d", i)
		}
	}
}

func TestDetMngAdd(t *testing.T) {

}
