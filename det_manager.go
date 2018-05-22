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

type JSqDet struct {
	// Unit: true for "for all", false for "exists"
	Unit bool `json:"unit"`
	// RDs resource determinators
	RDs []*ResDet `json:"rDs"`
	// ChL: children's length
	ChL uint32 `json:"chL"`
}

func (d *DetMng) SrvDet(w h.ResponseWriter, r *h.Request) {
	// serve det by index, default 0
	// index comes in URL
	i := reqIndex(r)
	dt := detIndexPreorder(d.MainDet, i)
	var e error
	if dt != nil {
		v := toJSqDet(dt)
		var bs []byte
		bs, e = json.Marshal(v)
		if e == nil {
			w.Write(bs)
		}
	} else {
		e = NoDetFound()
	}
	writeErr(w, e)
}

func toJSqDet(s *SqDet) (q *JSqDet) {
	q = &JSqDet{
		RDs:  s.RDs,
		Unit: s.Unit,
		ChL:  uint32(len(s.SDs)),
	}
	// the amount of children subtrees if not leaf
	// since the tree is walked in preorder the children's indexes
	// is predictible knowing the parent's inedex
	return
}

func detIndexPreorder(s *SqDet, n uint32) (d *SqDet) {
	ds, i := []*SqDet{s}, uint32(0)
	d = ds[0]
	for i != n && len(ds) != 0 {
		d = ds[len(ds)-1]
		ds = append(ds[:len(ds)-1], d.SDs...)
		i = i + 1
	}
	if i != n {
		println("ok")
		d = nil
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
		rt := detIndexPreorder(d.MainDet, i)
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
		rt := detIndexPreorder(d.MainDet, i)
		if rt != nil {
			rt.SDs = append(rt.SDs, rd)
		} else {
			e = NoDetFound()
		}
	}
	writeErr(w, e)
}

func NoDetFound() (e error) {
	e = fmt.Errorf("No Det found using detIndexPreorder")
	return
}
