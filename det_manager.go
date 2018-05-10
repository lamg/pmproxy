package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io/ioutil"
	h "net/http"
)

type DetMng struct {
	MainDet *SqDet
	Router  *mux.Router
}

type PrefixHandler struct {
	Prefix string
	Hnd    h.Handler
}

func (d *DetMng) Add(ph ...PrefixHandler) {
	for _, j := range ph {
		d.Router.Handle(j.Prefix, j.Hnd)
	}
}

const (
	Index = "index"
)

func (d *DetMng) SrvDet(w h.ResponseWriter, r *h.Request) {
	// serve det by index, default 0
	// index comes in URL
	i := reqIndex(r)
	dt := detIndexBFS(d.MainDet, i)
	var e error
	if dt != nil {
		e = Encode(w, dt)
	}
	writeErr(w, e)
}

func detIndexBFS(s *SqDet, n uint32) (d *SqDet) {
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
		var ok bool
		d, ok = ds[0].(*SqDet)
		println(ok)
	}
	return
}

func reqIndex(r *h.Request) (i uint32) {
	di := mux.Vars(r)
	ind, ok := di[Index]
	if ok {
		fmt.Sscan(ind, &i)
	}
	return
}

func (d *DetMng) SrvAddResDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	bs, e := ioutil.ReadAll(r.Body)
	rd := new(ResDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	rt := detIndexBFS(d.MainDet, i)
	if rt != nil {
		rt.Ds = append(rt.Ds, rd)
	} else {
		// error
	}
}

func (d *DetMng) SrvAddSqDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	bs, e := ioutil.ReadAll(r.Body)
	rd := new(ResDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	rt := detIndexBFS(d.MainDet, i)
	if rt != nil {
		fmt.Printf("rt: %v\n", rt)
		rt.Ds = append(rt.Ds, rd)
		fmt.Printf("rt: %v\n", rt.Ds[0])
	} else {
		// error
	}
}
