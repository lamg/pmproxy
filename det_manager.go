package pmproxy

import (
	"github.com/gorilla/mux"
)

type DetMng struct {
	MainDet *SqDet
	Router  *mux.Router
}

func (d *DetMng) Add() {

}
