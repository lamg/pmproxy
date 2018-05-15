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
	ds, i := []*SqDet{s}, uint32(0)
	for i != n && len(ds) != 0 {
		v := ds[0]
		ds = append(ds[1:], v.SDs...)
		i = i + 1
	}
	if len(ds) != 0 {
		d = ds[0]
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
	if e == nil {
		rt := detIndexBFS(d.MainDet, i)
		if rt != nil {
			rt.RDs = append(rt.RDs, rd)
		} else {
			e = NoDetFound()
		}
	}
	writeErr(w, e)
}

func (d *DetMng) SrvAddSqDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	bs, e := ioutil.ReadAll(r.Body)
	rd := new(SqDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	if e == nil {
		rt := detIndexBFS(d.MainDet, i)
		if rt != nil {
			rt.SDs = append(rt.SDs, rd)
		} else {
			e = NoDetFound()
		}
	}
	writeErr(w, e)
}

func NoDetFound() (e error) {
	e = fmt.Errorf("No Det found using detIndexBFS")
	return
}
