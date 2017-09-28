package main

import (
	"bytes"
	"fmt"
	"github.com/gotk3/gotk3/gtk"
	h "net/http"
)

type mainW struct {
	bx            *gtk.Box
	ust, pst, adr *gtk.Entry
	ent           *gtk.Button
	info          *gtk.Label
}

func initW(a *gtk.Application) (e error) {
	mw := new(mainW)
	mw.bx, e = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	if e == nil {
		mw.ust, e = gtk.EntryNew()
	}
	if e == nil {
		mw.pst, e = gtk.EntryNew()
	}
	if e == nil {
		mw.adr, e = gtk.EntryNew()
	}
	if e == nil {
		mw.pst.SetVisibility(false)
		mw.ent, e = gtk.ButtonNewWithLabel("Entrar")
	}
	if e == nil {
		mw.ent.Connect("clicked", mw.entClicked)
		mw.bx.PackStart(mw.adr, true, true, 0)
		mw.bx.PackStart(mw.ust, true, true, 0)
		mw.bx.PackStart(mw.pst, true, true, 0)
		mw.bx.PackStart(mw.ent, true, true, 0)
	}
	// TODO
	return
}

func (m *mainW) entClicked(b *gtk.Button, d interface{}) {
	adr, _ := m.adr.GetText()
	ust, _ := m.ust.GetText()
	pst, _ := m.ust.GetText()
	r, e := h.Post(adr, "text/json", bytes.NewBufferString(
		fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ust, pst)))
	if e == nil {
		m.info.SetText(r.Status)
	} else {
		m.info.SetText(e.Error())
	}
}
