package main

import (
	"fmt"
	h "net/http"

	"github.com/c2h5oh/datasize"
	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
)

type infoSt struct {
	// Shows user consumption
	ucs *gtk.Label
	// Shows user quota
	uqt *gtk.Label
	// Refreshs ucs and uqt
	rfr *gtk.Button
	le  *loginSt
	inf *gtk.Label
}

func newInfoBox(le *loginSt) (bx *gtk.Box, e error) {
	bx, e = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	var st *infoSt
	if e == nil {
		st = &infoSt{le: le}
		st.ucs, e = gtk.LabelNew("Consumo de usuario")
	}
	if e == nil {
		st.uqt, e = gtk.LabelNew("Quota de usuario")
	}
	if e == nil {
		st.inf, e = gtk.LabelNew("Info")
	}
	if e == nil {
		st.rfr, e = gtk.ButtonNewWithLabel("Actualizar")
	}
	if e == nil {
		st.rfr.Connect("clicked", st.rfrClicked)
	}
	if e == nil {
		bx.PackStart(st.ucs, true, true, 1)
		bx.PackStart(st.uqt, true, true, 1)
		bx.PackStart(st.rfr, true, true, 1)
		bx.PackStart(st.inf, true, true, 1)
	}
	return
}

func (st *infoSt) rfrClicked(b *gtk.Button) {
	adr, e := st.le.adr.GetText()
	var q *h.Request
	if e == nil {
		q, e = h.NewRequest(h.MethodGet,
			adr+pmproxy.UserStatus, nil)
	}
	var r *h.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, st.le.lr.Scrt)
		r, e = h.DefaultClient.Do(q)
	}
	var qc *pmproxy.QtCs
	if e == nil {
		qc = new(pmproxy.QtCs)
		ec := pmproxy.Decode(r.Body, qc)
		if ec != nil {
			e = ec.Err
		}
	}
	if e == nil {
		st.uqt.SetText(fmt.Sprintf("Cuota %s",
			datasize.ByteSize(qc.Quota).HumanReadable()))
		st.ucs.SetText(fmt.Sprintf("Consumo %s",
			datasize.ByteSize(qc.Consumption).HumanReadable()))
		st.inf.SetText(fmt.Sprintf("Usuario %s",
			st.le.usr.UserName))
	} else {
		st.inf.SetText(e.Error())
	}
}
