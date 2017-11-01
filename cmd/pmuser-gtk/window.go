package main

import (
	"crypto/tls"
	"io"
	h "net/http"

	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
)

func initW(a *gtk.Application, rd io.ReadCloser) (e error) {
	var w *gtk.ApplicationWindow
	w, e = gtk.ApplicationWindowNew(a)
	var st *gtk.Stack
	if e == nil {
		lg := new(loginInf)
		if rd != nil {
			pmproxy.Decode(rd, lg)
			rd.Close()
		}
		h.DefaultClient.Transport = &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		st, e = stack(lg)
	}
	var hd *gtk.HeaderBar
	if e == nil {
		hd, e = header(st)
	}
	if e == nil {
		w.SetIconName("system-users")
		w.SetTitlebar(hd)
		w.Add(st)
		w.SetDefaultSize(400, 200)
		w.Connect("destroy", a.Quit)
		w.ShowAll()
	}
	return
}

func stack(lg *loginInf) (st *gtk.Stack, e error) {
	var infoBx *gtk.Box
	var le *loginSt
	le, e = newLoginBox(lg)
	if e == nil {
		infoBx, e = newInfoBox(le)
	}
	var ctrlBx *gtk.Box
	if e == nil {
		ctrlBx, e = newCtrlSt(le)
	}
	if e == nil {
		st, e = gtk.StackNew()
	}
	if e == nil {
		st.AddTitled(le.bx, "login", "Autenticación")
		st.AddTitled(infoBx, "info", "Información")
		st.AddTitled(ctrlBx, "ctrl", "Administración")
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

func stSwtch(st *gtk.Stack) (stw *gtk.StackSwitcher, e error) {
	stw, e = gtk.StackSwitcherNew()
	if e == nil {
		stw.SetStack(st)
		stw.SetHAlign(gtk.ALIGN_CENTER)
	}
	return
}
