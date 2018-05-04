package pmproxy

import (
	"github.com/gorilla/mux"
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

func (d *DetMng) Add(ph []PrefixHandler) {
	for _, j := range ph {
		d.Router.Handle(j.Prefix, j.Hnd)
	}
}
