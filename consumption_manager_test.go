package pmproxy

import (
	"fmt"
	h "net/http"
	"sync"
	"testing"
	"time"

	"github.com/jinzhu/now"
	"github.com/lamg/clock"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestServeCons(t *testing.T) {
	cm, omp := NewCMng("cm"), map[string]uint64{
		"coco": 332,
		"pepe": 54,
		"kiko": 20331,
	}
	for k, v := range omp {
		cm.Cons.Store(k, v)
	}
	hnd := cm.PrefixHandler().Hnd
	w, r := reqres(t, h.MethodGet, "/"+cm.Name, "", "", "0.0.0.0")
	hnd.ServeHTTP(w, r)
	require.Equal(t, h.StatusOK, w.Code)
	mp := make(map[string]uint64)
	e := Decode(w.Body, &mp)
	require.NoError(t, e)
	require.Equal(t, omp, mp)
}

func TestServeUserCons(t *testing.T) {
	cm, omp := NewCMng("cm"), map[string]uint64{
		"coco": 332,
		"pepe": 54,
		"kiko": 20331,
	}
	for k, v := range omp {
		cm.Cons.Store(k, v)
	}
	for k, v := range omp {
		w, r := reqres(t, h.MethodGet, "/"+UserVar, "", "", "0.0.0.0")
		rq := mux.SetURLVars(r, map[string]string{UserVar: k})
		cm.ServeUserCons(w, rq)
		require.Equal(t, h.StatusOK, w.Code)
		rv := uint64(0)
		fmt.Fscanf(w.Body, "%d", &rv)
		require.Equal(t, v, rv)
	}
}

func TestModUsrCons(t *testing.T) {
	cm, omp := NewCMng("cm"), map[string]uint64{
		"coco": 332,
		"pepe": 54,
		"kiko": 20331,
		"zuzo": 1,
	}
	for k, v := range omp {
		cm.Cons.Store(k, v)
	}
	for k, v := range omp {
		nv := fmt.Sprintf("%d", v-1)
		w, r := reqres(t, h.MethodPut, "/"+UserVar, nv, "", "0.0.0.0")
		rq := mux.SetURLVars(r, map[string]string{UserVar: k})
		cm.ServeModUsrCons(w, rq)
		lv, ok := cm.Cons.Load(k)
		require.Equal(t, nv != "0", ok)
		if ok {
			require.Equal(t, v-1, lv.(uint64))
		}
	}
}

func TestMarshal(t *testing.T) {
	cm, omp := NewCMng("cm"), map[string]uint64{
		"coco": 332,
		"pepe": 54,
		"kiko": 20331,
		"zuzo": 1,
	}
	for k, v := range omp {
		cm.Cons.Store(k, v)
	}
	bs, e := cm.MarshalJSON()
	require.NoError(t, e)
	cm0 := NewCMng("coco")
	e = cm0.UnmarshalJSON(bs)
	require.NoError(t, e)
	require.Equal(t, cm.Name, cm0.Name)
	cm0.Cons.Range(func(k, v interface{}) (c bool) {
		lv, ok := cm.Cons.Load(k)
		require.True(t, ok)
		require.Equal(t, v, lv)
		c = true
		return
	})
}

func TestResetCons(t *testing.T) {
	initialDate := now.MustParse("2006-04-05")
	cl := &clock.TClock{
		Intv: time.Minute,
		Time: initialDate,
	}
	cm := &CMng{
		Cl:         cl,
		Cons:       new(sync.Map),
		LastReset:  initialDate,
		Name:       "cm",
		ResetCycle: time.Hour,
	}
	kiko := "kiko"
	adr := cm.Adder(kiko)
	for i := 0; i != 61; i++ {
		adr.Add(10)
		v, _ := adr.cons.Cons.Load(kiko)
		n := v.(uint64)
		require.Equal(t, i == 60 || i == 0, n == 10, "At %d", i)
	}
}
