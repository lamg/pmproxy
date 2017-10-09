package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/gotk3/gotk3/gtk"
	"github.com/lamg/pmproxy"
	"io"
	"io/ioutil"
	h "net/http"
	"os"
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
		st, e = stack(lg)
	}
	var hd *gtk.HeaderBar
	if e == nil {
		hd, e = header(st)
	}
	if e == nil {
		h.DefaultClient.Transport = &h.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		w.SetIconName("system-users")
		w.SetTitlebar(hd)
		w.Add(st)
		w.SetDefaultSize(400, 200)
		w.Connect("destroy", a.Quit)
		w.ShowAll()
	}
	return
}

type loginInf struct {
	Addr string `json:"addr"`
	User string `json:"user"`
	Pass string `json:"pass"`
}

func stack(lg *loginInf) (st *gtk.Stack, e error) {
	var infoBx *gtk.Box
	var le *loginSt
	le, e = newLoginBox(lg)
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
		st.ent, e = gtk.ButtonNewWithLabel("Entrar")
	}
	if e == nil {
		st.inf, e = gtk.LabelNew("Info")
	}
	if e == nil {
		st.inf.SetLineWrap(true)
		st.ent.Connect("clicked", st.entClicked)
		st.bx.PackStart(st.adr, false, true, 0)
		st.bx.PackStart(st.ust, false, true, 0)
		st.bx.PackStart(st.pst, false, true, 0)
		st.bx.PackStart(st.ent, false, true, 0)
		st.bx.PackStart(st.inf, false, true, 0)
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
		bx.PackStart(st.ucs, false, true, 0)
		bx.PackStart(st.uqt, false, true, 0)
		bx.PackStart(st.rfr, false, true, 0)
		bx.PackStart(st.inf, false, false, 0)
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
	jusr := fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ust, pst)
	r, e := h.Post(adr+pmproxy.LogX, "text/json",
		bytes.NewBufferString(jusr))
	if e == nil {
		var bs []byte
		bs, _ = ioutil.ReadAll(r.Body)
		r.Body.Close()
		sb := string(bs)
		if len(sb) > 70 {
			sb = sb[:70] + "…"
		}
		m.inf.SetText(fmt.Sprintf("Respuesta: %s Cuerpo:%s",
			r.Status, sb))
		if r.StatusCode == h.StatusOK {
			m.scr = bs
			f, _ := os.Create(config)
			if f != nil {
				lg := &loginInf{Addr: adr, User: ust, Pass: pst}
				pmproxy.Encode(f, lg)
				f.Close()
			}
		}
	}
	if e != nil {
		m.inf.SetText(fmt.Sprintf("Error: %s", e.Error()))
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
	var bs []byte
	if e == nil {
		bs, e = ioutil.ReadAll(r.Body)
		r.Body.Close()
	}
	var ust *pmproxy.UsrSt
	if e == nil {
		ust = new(pmproxy.UsrSt)
		e = json.Unmarshal(bs, ust)
		if e != nil {
			sb := string(bs)
			if len(sb) > 70 {
				sb = sb[:70] + "…"
			}
			e = fmt.Errorf("Error: %s Body: %s", e.Error(), sb)
		}
	}
	if e == nil {
		st.uqt.SetText(fmt.Sprintf("Cuota %s",
			datasize.ByteSize(ust.Quota).HumanReadable()))
		st.ucs.SetText(fmt.Sprintf("Consumo %s",
			datasize.ByteSize(ust.Consumption).HumanReadable()))
		st.inf.SetText(fmt.Sprintf("Usuario %s", ust.UserName))
	} else {
		st.inf.SetText(e.Error())
	}
}
