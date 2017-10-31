package main

import (
	"bytes"
	h "net/http"

	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
)

type ctrlSt struct {
	usrEnt *gtk.Entry
	consSp *gtk.SpinButton
	setBt  *gtk.Button
	infoLb *gtk.Label
	ls     *loginSt
}

func newCtrlSt(ls *loginSt) (bx *gtk.Box, e error) {
	cs := &ctrlSt{ls: ls}
	cs.usrEnt, e = gtk.EntryNew()
	if e == nil {
		cs.consSp, e = gtk.SpinButtonNew(nil, 1, 0)
	}
	if e == nil {
		cs.setBt, e = gtk.ButtonNewWithLabel("Asignar consumo")
	}
	if e == nil {
		cs.infoLb, e = gtk.LabelNew("Info")
	}
	if e == nil {
		bx, e = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 1)
	}
	if e == nil {
		cs.setBt.Connect("clicked", cs.setCons)
		bx.PackStart(cs.usrEnt, true, true, 1)
		bx.PackStart(cs.consSp, true, true, 1)
		bx.PackStart(cs.setBt, true, true, 1)
		bx.PackStart(cs.infoLb, true, true, 1)
	}
	return
}

func (cs *ctrlSt) setCons(b *gtk.Button) {
	usr, e := cs.usrEnt.GetText()
	var addr string
	if e == nil {
		addr, e = cs.ls.adr.GetText()
	}
	var bf *bytes.Buffer
	if e == nil {
		cons := uint64(cs.consSp.GetValue())
		ust := &pmproxy.NameVal{
			Name:  usr,
			Value: cons,
		}
		bf = bytes.NewBufferString("")
		ec := pmproxy.Encode(bf, ust)
		if ec != nil {
			e = ec.Err
		}
	}
	var r *h.Request
	if e == nil {
		r, e = h.NewRequest(h.MethodPut,
			addr+pmproxy.UserStatus, bf)
	}
	var p *h.Response
	if e == nil {
		r.Header.Set(pmproxy.AuthHd, cs.ls.lr.Scrt)
		p, e = h.DefaultClient.Do(r)
	}
	if e == nil {
		cs.infoLb.SetText(p.Status)
	} else {
		cs.infoLb.SetText("Error: " + e.Error())
	}
}
