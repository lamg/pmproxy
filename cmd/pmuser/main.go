package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/c2h5oh/datasize"
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
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	osUsr, e := user.Current()
	var fl io.ReadCloser
	var cfPath string
	var d error
	if e == nil {
		cfPath = path.Join(osUsr.HomeDir, conf)
		fl, d = os.Open(cfPath)
	}
	var bs []byte
	if e == nil {
		bs, e = ioutil.ReadAll(fl)
	}
	cf := new(Conf)
	if e == nil && d == nil {
		e = yaml.Unmarshal(bs, cf)
		fl.Close()
	}
	var u *ui
	var tu tui.UI
	if e == nil {
		u = newUi(cf, cfPath)
		tu, e = tui.New(u.box)
	}
	if e == nil {
		tu.SetKeybinding("Esc", func() { tu.Quit() })
		e = tu.Run()
	}
	if e != nil {
		log.Print(e.Error())
	}
	// var user, pass, proxyAddr string
	// flag.StringVar(&user, "u", "", "User name to login")
	// flag.StringVar(&pass, "p", "", "Password to login")
	// flag.StringVar(&proxyAddr, "a", "", "Proxy address")
	// flag.Parse()

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
	sessB, qcB, qcuB *tui.Button
	box              *tui.Box
	scrt             string
	proxyAddr        string
}

func newUi(cf *Conf, cfPath string) (u *ui) {
	u = new(ui)
	u.proxyAddr = cf.ProxyAddr
	u.user, u.pass = tui.NewEntry(), tui.NewEntry()
	u.user.SetText(cf.User)
	u.pass.SetText(cf.Pass)
	u.sessB, u.qcB, u.qcuB, u.wrkArea = tui.NewButton("[Sesión]"),
		tui.NewButton("[Cuota y consumo]"),
		tui.NewButton("[Cuota y consumo de otro usuario]"),
		tui.NewVBox()
	u.sidebar = tui.NewVBox(u.sessB, u.qcB, u.qcuB)
	u.sidebar.SetBorder(true)
	u.sessB.OnActivated(func(b *tui.Button) { u.showLoginBox() })
	u.qcB.OnActivated(func(b *tui.Button) { u.showQC() })
	u.qcuB.OnActivated(func(b *tui.Button) { u.showUsrQC() })
	hb := tui.NewHBox(u.sidebar, u.wrkArea)
	u.status = tui.NewStatusBar("Listo.")
	u.box = tui.NewVBox(hb, u.status)
	tui.DefaultFocusChain.Set(u.sessB, u.qcB, u.qcuB)
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
		u.logout()
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

	tui.DefaultFocusChain.Set(u.user, u.pass, login, logout,
		u.qcB, u.qcuB, u.sessB)
	tui.DefaultFocusChain.FocusNext(u.sessB)
	u.wrkArea.Append(window)
}

func (u *ui) showQC() {
	u.wrkArea.Remove(0)
	cons, e := get(u.proxyAddr, pmproxy.UserStatus, u.scrt)
	var qc *pmproxy.QtCs
	if e == nil {
		qc = new(pmproxy.QtCs)
		e = json.Unmarshal(cons, qc)
	}
	var msg string
	if e == nil {
		qt, cs := datasize.ByteSize(qc.Quota),
			datasize.ByteSize(qc.Consumption)
		msg = fmt.Sprintf("Cuota: %s Consumo: %s",
			qt.HumanReadable(), cs.HumanReadable())

	} else {
		msg = e.Error()
	}
	lb := tui.NewLabel(msg)
	u.wrkArea.Append(lb)
}

func (u *ui) showUsrQC() {
	u.wrkArea.Remove(0)
	ue, bt, lb := tui.NewEntry(), tui.NewButton("[Obtener]"),
		tui.NewLabel("Cuota y consumo del usuario introducido")
	bt.OnActivated(func(b *tui.Button) {
		r, e := http.Post(u.proxyAddr+pmproxy.UserStatus,
			"text/plain", bytes.NewBufferString(ue.Text()))
		var qc *pmproxy.QtCs
		if e == nil {
			qc = new(pmproxy.QtCs)
			ec := pmproxy.Decode(r.Body, qc)
			if ec != nil {
				e = ec.Err
			}
		}
		if e == nil {
			lb.SetText(fmt.Sprintf("Cuota: %s Consumo: %s",
				datasize.ByteSize(qc.Quota).HumanReadable(),
				datasize.ByteSize(qc.Consumption).HumanReadable()))
		} else {
			lb.SetText(e.Error())
		}
	})

	tui.DefaultFocusChain.Set(ue, bt, u.sessB, u.qcB, u.qcuB)
	ue.SetFocused(true)
	bx := tui.NewVBox(ue, bt, lb)
	u.wrkArea.Append(bx)
}

func (u *ui) login() {
	cr := &credentials{u.user.Text(), u.pass.Text()}
	bs, e := json.Marshal(&cr)
	var r *http.Response
	if e == nil {
		r, e = http.Post(u.proxyAddr+pmproxy.LogX, "text/json",
			bytes.NewReader(bs))
	}
	var lr *pmproxy.LogRs
	if e == nil {
		lr = new(pmproxy.LogRs)
		ec := pmproxy.Decode(r.Body, lr)
		if ec != nil {
			e = ec.Err
		}
		r.Body.Close()
	}
	if e == nil {
		u.scrt = lr.Scrt
		u.status.SetText("Sesión abierta.")
	} else {
		u.status.SetText(e.Error())
	}
}

func (u *ui) logout() {
	q, e := http.NewRequest(http.MethodDelete,
		u.proxyAddr+pmproxy.LogX, nil)
	var r *http.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, u.scrt)
		r, e = http.DefaultClient.Do(q)
	}
	if e == nil {
		if r.StatusCode == http.StatusOK {
			u.status.SetText("Sesión cerrada")
		} else {
			u.status.SetText(
				fmt.Sprintf("El servidor devolvió %d", r.StatusCode))
		}
	} else {
		u.status.SetText(e.Error())
	}
}

func get(addr, path, hd string) (bs []byte, e error) {
	var q *http.Request
	q, e = http.NewRequest(http.MethodGet, addr+path, nil)
	var p *http.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, hd)
		p, e = http.DefaultClient.Do(q)
	}
	if e == nil {
		bs, e = ioutil.ReadAll(p.Body)
	}
	return
}
