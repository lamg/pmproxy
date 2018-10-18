package main

import (
	"github.com/gotk3/gotk3/gtk"
)

/*
Functionality
- login as an user
- login as an admin
- show and modify rules
- show and modify managers

*/

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
		w.SetDefaultSize(400, 200)
		w.Connect("destroy", a.Quit)
		w.ShowAll()
	}
	return
}

func stack() (st *gtk.Stack, e error) {
	var usrLog *gtk.Box
	usrLog, e = loginBox("user/login/api/path")
	var admLog *gtk.Box
	if e == nil {
		admLog, e = loginBox("adm/login/api/path")
	}
	var rules *gtk.Box
	if e == nil {

	}
	var mngs *gtk.Box
	if e == nil {

	}
	return
}

func header(st *gtk.Stack) (hd *gtk.HeaderBar, e error) {
	var swt *gtk.StackSwitcher
	swt, e = gtk.StackSwitcherNew()
	if e == nil {
		swt.SetStack(st)
		swt.SetHAlign(gtk.ALIGN_CENTER)
	}
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
