package main

import (
	"github.com/lamg/errors"
	"github.com/lamg/pmproxy"
	"github.com/marcusolsson/tui-go"
	"io/ioutil"
	"log"
	"net/http"
)

type credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func main() {
	u := newUi()
	ui, e := tui.New(u.box)
	if e == nil {
		ui.SetKeybinding("Esc", func() { ui.Quit() })
		e = ui.Run()
	}
	if e != nil {
		log.Print(e.Error())
	}
	// var user, pass, proxyAddr string
	// flag.StringVar(&user, "u", "", "User name to login")
	// flag.StringVar(&pass, "p", "", "Password to login")
	// flag.StringVar(&proxyAddr, "a", "", "Proxy address")
	// flag.Parse()

	// cr := &credentials{user, pass}
	// bs, e := json.Marshal(&cr)
	// var r *http.Response
	// if e == nil {
	// 	http.DefaultClient.Transport = &http.Transport{
	// 		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// 	}
	// 	r, e = http.Post(proxyAddr+pmproxy.LogX, "text/json",
	// 		bytes.NewReader(bs))
	// }
	// var lr *pmproxy.LogRs
	// if e == nil {
	// 	lr = new(pmproxy.LogRs)
	// 	e = pmproxy.Decode(r.Body, lr)
	// 	r.Body.Close()
	// }
	// var cons string
	// if e == nil {
	// 	cons, e = get(proxyAddr, pmproxy.UserStatus, lr.Scrt)
	// }
	// if e == nil {
	// 	log.Print(cons)
	// }

}

var logo = `
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
`

type ui struct {
	sidebar, wrkArea *tui.Box
	sessB, qcB       *tui.Button
	box              *tui.Box
	scrt             string
}

func newUi() (u *ui) {
	u = new(ui)
	u.sessB, u.qcB, u.wrkArea = tui.NewButton("[Sesión]"),
		tui.NewButton("[Cuota y consumo]"),
		tui.NewVBox()
	u.sidebar = tui.NewVBox(u.sessB, u.qcB)
	u.sidebar.SetBorder(true)
	u.sessB.OnActivated(func(b *tui.Button) { u.showLoginBox() })
	u.qcB.OnActivated(func(b *tui.Button) { u.showQC() })
	u.box = tui.NewHBox(u.sidebar, u.wrkArea)
	tui.DefaultFocusChain.Set(u.sessB, u.qcB)
	return
}

func (u *ui) showLoginBox() {
	u.wrkArea.Remove(0)

	user := tui.NewEntry()
	user.SetFocused(true)

	pass := tui.NewEntry()
	pass.SetEchoMode(tui.EchoModePassword)

	form := tui.NewGrid(0, 0)
	form.AppendRow(
		tui.NewLabel("Usuario"),
		tui.NewLabel("Contraseña"),
	)
	form.AppendRow(user, pass)
	status := tui.NewStatusBar("Listo.")

	login := tui.NewButton("[Abrir]")
	login.OnActivated(func(b *tui.Button) {
		status.SetText("Sesión abierta.")
	})

	logout := tui.NewButton("[Cerrar]")
	logout.OnActivated(func(b *tui.Button) {
		status.SetText("Sesión cerrada")
	})

	tui.DefaultFocusChain.Set(user, pass, login, logout, u.qcB,
		u.sessB)
	u.wrkArea.Append(form)
}

func (u *ui) showQC() {
	u.wrkArea.Remove(0)
	lb := tui.NewLabel("Estado de cuota y consumo")
	u.wrkArea.Append(lb)
}

func get(addr, path, hd string) (r string, e *errors.Error) {
	var q *http.Request
	if e == nil {
		var ec error
		q, ec = http.NewRequest(http.MethodGet, addr+path, nil)
		e = errors.NewForwardErr(ec)
	}
	var p *http.Response
	if e == nil {
		var ec error
		q.Header.Set(pmproxy.AuthHd, hd)
		p, ec = http.DefaultClient.Do(q)
		e = errors.NewForwardErr(ec)
	}
	var bs []byte
	if e == nil {
		var ec error
		bs, ec = ioutil.ReadAll(p.Body)
		e = errors.NewForwardErr(ec)
	}
	if e == nil {
		r = string(bs)
	}
	return
}
