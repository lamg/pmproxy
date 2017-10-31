package main

import (
	"bytes"
	"fmt"
	h "net/http"
	"os"

	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
)

type loginInf struct {
	Addr string `json:"addr"`
	User string `json:"user"`
	Pass string `json:"pass"`
	Scrt string `json:"scrt"`
}

type loginSt struct {
	adr *gtk.Entry
	ust *gtk.Entry
	pst *gtk.Entry
	inf *gtk.Label
	ent *gtk.Button
	bx  *gtk.Box
	lr  *pmproxy.LogRs
	usr *pmproxy.User
}

func newLoginBox(lg *loginInf) (st *loginSt, e error) {
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
		st.adr.SetText(lg.Addr)
		st.ust.SetText(lg.User)
		st.pst.SetText(lg.Pass)
		st.lr = &pmproxy.LogRs{Scrt: lg.Scrt}
		y := isLogged(lg.Addr, lg.Scrt)
		var btTxt string
		if y {
			btTxt = "Salir"
		} else {
			btTxt = "Entrar"
		}
		st.ent, e = gtk.ButtonNewWithLabel(btTxt)
	}
	if e == nil {
		st.inf, e = gtk.LabelNew("Info")
	}
	if e == nil {
		st.inf.SetLineWrap(true)
		st.ent.Connect("clicked", st.entClicked)
		st.bx.PackStart(st.adr, true, true, 1)
		st.bx.PackStart(st.ust, true, true, 1)
		st.bx.PackStart(st.pst, true, true, 1)
		st.bx.PackStart(st.ent, true, true, 1)
		st.bx.PackStart(st.inf, true, true, 1)
	}
	return
}

func isLogged(addr, scrt string) (y bool) {
	y = false
	q, e := h.NewRequest(h.MethodGet, addr+pmproxy.CheckUser,
		nil)
	var r *h.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, scrt)
		r, e = h.DefaultClient.Do(q)
	}
	y = e == nil && r.StatusCode == h.StatusOK
	return
}

func (m *loginSt) entClicked(b *gtk.Button) {
	adr, e := m.adr.GetText()
	if e == nil {
		y := isLogged(adr, m.lr.Scrt)
		if y {
			m.logout(b, adr)
		} else {
			m.login(b, adr)
		}
	}
}

func (m *loginSt) logout(b *gtk.Button, adr string) (e error) {
	var q *h.Request
	q, e = h.NewRequest(h.MethodDelete, adr+pmproxy.LogX, nil)
	var r *h.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, m.lr.Scrt)
		r, e = h.DefaultClient.Do(q)
	}
	if e == nil && r.StatusCode == h.StatusOK {
		b.SetLabel("Entrar")
		m.inf.SetText("OK")
	} else if e == nil {
		m.inf.SetText(fmt.Sprintf("Error: %d", r.StatusCode))
	} else {
		m.inf.SetText(e.Error())
	}
	return
}

func (m *loginSt) login(b *gtk.Button, adr string) (e error) {
	var ust string
	ust, e = m.ust.GetText()
	var pst string
	if e == nil {
		pst, e = m.pst.GetText()
	}
	var r *h.Response
	if e == nil {
		jusr := fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ust, pst)
		r, e = h.Post(adr+pmproxy.LogX, "text/json",
			bytes.NewBufferString(jusr))
		if e == nil {
			m.lr = new(pmproxy.LogRs)
			er := pmproxy.Decode(r.Body, m.lr)
			if er != nil {
				e = er.Err
			}
		}
	}
	var q *h.Request
	if e == nil {
		q, e = h.NewRequest(h.MethodGet, adr+pmproxy.UserInfo,
			nil)
	}
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, m.lr.Scrt)
		r, e = h.DefaultClient.Do(q)
	}
	if e == nil {
		m.usr = new(pmproxy.User)
		pmproxy.Decode(r.Body, m.usr)
		r.Body.Close()
	}
	if e == nil {
		m.inf.SetText(fmt.Sprintf("Respuesta: %s Usuario:%s",
			r.Status, m.usr.Name))
		b.SetLabel("Salir")
		if r.StatusCode == h.StatusOK {
			f, _ := os.Create(config)
			if f != nil {
				lg := &loginInf{
					Addr: adr,
					User: ust,
					Pass: pst,
					Scrt: m.lr.Scrt,
				}
				pmproxy.Encode(f, lg)
				f.Close()
			}
		}
	}
	if e != nil {
		m.inf.SetText(fmt.Sprintf("Error: %s", e.Error()))
	}
	return
}
