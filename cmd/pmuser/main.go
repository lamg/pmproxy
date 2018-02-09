package main

import (
	"bytes"
	"encoding/json"
	"github.com/lamg/errors"
	"github.com/lamg/pmproxy"
	"github.com/marcusolsson/tui-go"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"path"
)

type credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type Conf struct {
	User      string `yaml:"user"`
	Pass      string `yaml:"pass"`
	ProxyAddr string `yaml:"proxyAddr"`
}

const conf = ".pmuser.yaml"

func main() {
	osUsr, e := user.Current()
	var fl io.ReadCloser
	var cfPath string
	var d error
	if e == nil {
		cfPath = path.Join(osUsr.HomeDir, conf)
		fl, d = os.Open(cfPath)
	}
	cf := new(Conf)
	if e == nil && d == nil {
		e = yaml.Unmarshal(fl, cf)
		fl.Close()
	}
	var u *ui
	if e == nil {
		u = newUi(cf, cfPath)
		ui, e = tui.New(u.box)
	}
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
	user, pass       *tui.Entry
	sidebar, wrkArea *tui.Box
	status           *tui.StatusBar
	sessB, qcB       *tui.Button
	box              *tui.Box
	scrt             string
	proxyAddr        string
}

func newUi(cf *Conf) (u *ui) {
	u = new(ui)
	u.proxyAddr = cf.ProxyAddr
	u.user, u.pass = tui.NewEntry(), tui.NewEntry()
	u.user.SetText(cf.User)
	u.pass.SetText(cf.Pass)
	u.sessB, u.qcB, u.wrkArea = tui.NewButton("[Sesión]"),
		tui.NewButton("[Cuota y consumo]"),
		tui.NewVBox()
	u.sidebar = tui.NewVBox(u.sessB, u.qcB)
	u.sidebar.SetBorder(true)
	u.sessB.OnActivated(func(b *tui.Button) { u.showLoginBox() })
	u.qcB.OnActivated(func(b *tui.Button) { u.showQC() })
	hb := tui.NewHBox(u.sidebar, u.wrkArea)
	u.status = tui.NewStatusBar("Listo.")
	u.box = tui.NewVBox(hb, u.status)
	tui.DefaultFocusChain.Set(u.sessB, u.qcB)
	return
}

func (u *ui) showLoginBox() {
	u.wrkArea.Remove(0)

	u.user.SetFocused(true)

	u.pass.SetEchoMode(tui.EchoModePassword)

	form := tui.NewGrid(0, 0)
	form.AppendRow(
		tui.NewLabel("Usuario"),
		tui.NewLabel("Contraseña"),
	)
	form.AppendRow(u.user, u.pass)

	login := tui.NewButton("[Abrir]")
	login.OnActivated(func(b *tui.Button) {
		u.login()
	})

	logout := tui.NewButton("[Cerrar]")
	logout.OnActivated(func(b *tui.Button) {
		u.status.SetText("Sesión cerrada")
	})

	buttons := tui.NewHBox(
		tui.NewSpacer(),
		tui.NewPadder(1, 0, login),
		tui.NewPadder(1, 0, logout),
	)

	lbLogo := tui.NewLabel(logo)
	window := tui.NewVBox(
		tui.NewPadder(10, 1, lbLogo),
		tui.NewPadder(12, 0, tui.NewLabel("Bienvenido a PMProxy")),
		tui.NewPadder(1, 1, form),
		buttons,
	)
	window.SetBorder(true)

	tui.DefaultFocusChain.Set(user, pass, login, logout, u.qcB,
		u.sessB)
	tui.DefaultFocusChain.FocusNext(u.sessB)
	u.wrkArea.Append(window)
}

func (u *ui) showQC() {
	u.wrkArea.Remove(0)
	lb := tui.NewLabel("Estado de cuota y consumo")
	u.wrkArea.Append(lb)
}

func (u *ui) login() {
	cr := &credentials{u.user.Text(), u.pass.Text()}
	bs, e := json.Marshal(&cr)
	var r *http.Response
	if e == nil {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		r, e = http.Post(u.proxyAddr+pmproxy.LogX, "text/json",
			bytes.NewReader(bs))
	}
	var lr *pmproxy.LogRs
	if e == nil {
		lr = new(pmproxy.LogRs)
		e = pmproxy.Decode(r.Body, lr)
		r.Body.Close()
	}
	if e == nil {
		u.scrt = lr.Scrt
		u.status.SetText("Sesión abierta.")
	} else {
		u.status.SetText(e.Error())
	}
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
