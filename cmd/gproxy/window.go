package main

import (
	"bytes"
	"fmt"
	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
	"io/ioutil"
	h "net/http"
)

func initW(a *gtk.Application) (e error) {
	var w *gtk.ApplicationWindow
	w, e = gtk.ApplicationWindowNew(a)
	var st *gtk.Stack
	if e == nil {
		st, e = stack()
	}
	var hd *gtk.HeaderBar
	if e == nil {
		hd, e = header(st)
	}
	if e == nil {
		w.SetIconName("system-users")
		w.SetTitlebar(hd)
		w.Add(st)
		w.SetDefaultSize(800, 600)
		w.Connect("destroy", a.Quit)
		w.ShowAll()
	}
	return
}

func stack() (st *gtk.Stack, e error) {
	var infoBx *gtk.Box
	var le *loginSt
	le, e = newLoginBox()
	if e == nil {
		infoBx, e = newInfoBox(le)
	}
	if e == nil {
		st, e = gtk.StackNew()
	}
	if e == nil {
		st.AddTitled(le.bx, "login", "Autenticación")
		st.AddTitled(infoBx, "info", "Información")
	}
	return
}

func header(st *gtk.Stack) (hd *gtk.HeaderBar, e error) {
	var swt *gtk.StackSwitcher
	swt, e = stSwtch(st)
	if e == nil {
		hd, e = gtk.HeaderBarNew()
	}
	if e == nil {
		hd.SetShowCloseButton(true)
		hd.SetCustomTitle(swt)
		hd.Set("has-subtitle", false)
	}
	return
}

func newLoginBox() (st *loginSt, e error) {
	st = new(loginSt)
	st.bx, e = gtk.BoxNew(gtk.ORIENTATION_VERTICAL, 0)
	if e == nil {
		st.ust, e = gtk.EntryNew()
	}
	if e == nil {
		st.pst, e = gtk.EntryNew()
	}
	if e == nil {
		st.adr, e = gtk.EntryNew()
	}
	if e == nil {
		st.pst.SetVisibility(false)
		st.ent, e = gtk.ButtonNewWithLabel("Entrar")
	}
	if e == nil {
		st.inf, e = gtk.LabelNew("Info")
	}
	if e == nil {
		st.ent.Connect("clicked", st.entClicked)
		st.bx.PackStart(st.adr, true, true, 0)
		st.bx.PackStart(st.ust, true, true, 0)
		st.bx.PackStart(st.pst, true, true, 0)
		st.bx.PackStart(st.ent, true, true, 0)
		st.bx.PackStart(st.inf, true, true, 0)
	}
	return
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
		bx.PackStart(st.ucs, true, true, 0)
		bx.PackStart(st.uqt, true, true, 0)
		bx.PackStart(st.rfr, true, true, 0)
		bx.PackStart(st.inf, true, true, 0)
	}
	return
}

func stSwtch(st *gtk.Stack) (stw *gtk.StackSwitcher, e error) {
	stw, e = gtk.StackSwitcherNew()
	if e == nil {
		stw.SetStack(st)
		stw.SetHAlign(gtk.ALIGN_CENTER)
	}
	return
}

type loginSt struct {
	adr *gtk.Entry
	ust *gtk.Entry
	pst *gtk.Entry
	inf *gtk.Label
	ent *gtk.Button
	bx  *gtk.Box
	scr []byte
}

func (m *loginSt) entClicked(b *gtk.Button) {
	adr, _ := m.adr.GetText()
	ust, _ := m.ust.GetText()
	pst, _ := m.pst.GetText()
	r, e := h.Post(adr+pmproxy.LogX, "text/json",
		bytes.NewBufferString(fmt.Sprintf(
			`{"user":"%s","pass":"%s"}`, ust, pst)))
	if e == nil {
		m.inf.SetText(fmt.Sprintf("Respuesta: %s", r.Status))
		m.scr, e = ioutil.ReadAll(r.Body)
	}
	if e != nil {
		m.inf.SetText(fmt.Sprintf("Error: %s", e.Error()))
	} else {
		r.Body.Close()
	}
}

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

func (st *infoSt) rfrClicked(b *gtk.Button) {
	adr, e := st.le.adr.GetText()
	var q *h.Request
	if e == nil {
		q, e = h.NewRequest(h.MethodGet,
			adr+pmproxy.UserStatus, nil)
	}
	var r *h.Response
	if e == nil {
		if st.le.scr != nil {
			q.Header.Set(pmproxy.AuthHd, string(st.le.scr))
			r, e = h.DefaultClient.Do(q)
		} else {
			e = fmt.Errorf("No ha iniciado sesión")
		}
	}
	var ust *pmproxy.UsrSt
	if e == nil {
		ust = new(pmproxy.UsrSt)
		ec := pmproxy.Decode(r.Body, ust)
		if ec != nil {
			e = ec.Err
		}
		r.Body.Close()
	}
	if e == nil {
		st.uqt.SetText(fmt.Sprintf("Cuota %d", ust.Quota))
		st.ucs.SetText(fmt.Sprintf("Consumo %d", ust.Consumption))
	} else {
		st.inf.SetText(e.Error())
	}
}
