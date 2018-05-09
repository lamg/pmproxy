package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
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
		d, _ = ds[0].(*SqDet)
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

func (d *DetMng) SrvAddDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	d.addDet(r.Body, i)
}

func (d *DetMng) addDet(r io.ReadCloser, i uint32) (ok bool) {
	var det Det
	bs, e := ioutil.ReadAll(r)
	rd := new(ResDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	s := new(SqDet)
	if e == nil {
		det = rd
	} else {
		e = json.Unmarshal(bs, s)
		if e == nil {
			det = s
		}
	}
	rt := detIndexBFS(d.MainDet, i)
	ok = rt != nil
	if ok {
		rt.Ds = append(rt.Ds, det)
	}
	return
}
