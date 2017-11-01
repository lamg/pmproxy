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
		st.inf, e = gtk.LabelNew("Info")
	}
	if e == nil {
		st.pst.SetVisibility(false)
		st.adr.SetText(lg.Addr)
		st.ust.SetText(lg.User)
		st.pst.SetText(lg.Pass)
		st.lr = &pmproxy.LogRs{Scrt: lg.Scrt}
		y := isLogged(lg.Addr, lg.Scrt)
		st.ent, e = gtk.ButtonNewWithLabel("")
		if e == nil {
			if y {
				e = st.updateAtLogin(lg.Addr)
			} else {
				e = st.updateAtLogout()
			}
		}
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
	var y bool
	if e == nil {
		y = isLogged(adr, m.lr.Scrt)
		if y {
			e = m.logout(b, adr)
		} else {
			e = m.login(b, adr)
		}
	}
	if e == nil {
		if y {
			e = m.updateAtLogout()
		} else {
			e = m.updateAtLogin(adr)
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
		m.updateAtLogout()
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
	if e == nil {
		lg := &loginInf{
			Addr: adr,
			User: ust,
			Pass: pst,
			Scrt: m.lr.Scrt,
		}
		writeConfig(lg)
		e = m.updateAtLogin(adr)
	}
	return
}

// updateAtLogin updates GUI to reflect the user is logged
func (m *loginSt) updateAtLogin(adr string) (e error) {
	var q *h.Request
	if e == nil {
		q, e = h.NewRequest(h.MethodGet, adr+pmproxy.UserInfo,
			nil)
	}
	var r *h.Response
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
		m.ent.SetLabel("Salir")
	}
	if e != nil {
		m.inf.SetText(fmt.Sprintf("Error: %s", e.Error()))
	}
	return
}

// updateAtLogout updates GUI to reflect no user is logged
func (m *loginSt) updateAtLogout() (e error) {
	m.ent.SetLabel("Entrar")
	m.inf.SetText("Sesión cerrada")
	m.lr.Scrt = ""
	return
}

func writeConfig(lg *loginInf) (e error) {
	var f *os.File
	f, e = os.Create(config)
	if e == nil {
		pmproxy.Encode(f, lg)
		f.Close()
	}
	return
}
