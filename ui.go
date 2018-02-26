package pmproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/marcusolsson/tui-go"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path"
)

var logo = `
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
`

type UConf struct {
	User      string `yaml:"user"`
	Pass      string `yaml:"pass"`
	ProxyAddr string `yaml:"proxyAddr"`
}

const UConfName = ".pmuser.yaml"

type UI struct {
	user, pass, proxy *tui.Entry
	sidebar, wrkArea  *tui.Box
	status            *tui.StatusBar
	sessB, qcB, qcuB  *tui.Button
	box               *tui.Box
	tu                tui.UI
	scrt              string
	proxyAddr         string
	conf              *UConf
}

func InitUI(isAdm bool) (ui *UI, e error) {
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	osUsr, e := user.Current()
	var fl io.ReadCloser
	var cfPath string
	var d error
	if e == nil {
		cfPath = path.Join(osUsr.HomeDir, UConfName)
		fl, d = os.Open(cfPath)
	}
	var bs []byte
	if e == nil && d == nil {
		bs, e = ioutil.ReadAll(fl)
	}
	cf := new(UConf)
	if e == nil && d == nil {
		e = yaml.Unmarshal(bs, cf)
		fl.Close()
	}
	if e == nil {
		ui = NewUI(cf, cfPath, isAdm)
		ui.tu, e = tui.New(ui.box)
	}
	if e == nil {
		ui.tu.SetKeybinding("Esc", func() { ui.tu.Quit() })
	}
	return
}

func NewUI(cf *UConf, cfPath string, isAdm bool) (u *UI) {
	u = new(UI)
	u.conf = cf
	u.proxyAddr = cf.ProxyAddr
	u.user, u.pass, u.proxy = tui.NewEntry(), tui.NewEntry(),
		tui.NewEntry()
	u.user.SetText(cf.User)
	u.pass.SetText(cf.Pass)
	u.proxy.SetText(cf.ProxyAddr)
	u.sessB, u.qcB, u.wrkArea = tui.NewButton("[Sesión]"),
		tui.NewButton("[Cuota y consumo]"),
		tui.NewVBox()
	if isAdm {
		u.qcuB = tui.NewButton("[Cuota y consumo de otro usuario]")
		u.sidebar = tui.NewVBox(u.sessB, u.qcB, u.qcuB)
		u.qcuB.OnActivated(func(b *tui.Button) { u.showUsrQC() })
		tui.DefaultFocusChain.Set(u.sessB, u.qcB, u.qcuB)
	} else {
		u.sidebar = tui.NewVBox(u.sessB, u.qcB)
		tui.DefaultFocusChain.Set(u.sessB, u.qcB)
	}
	u.sidebar.SetBorder(true)
	u.sessB.OnActivated(func(b *tui.Button) { u.showLoginBox() })
	u.qcB.OnActivated(func(b *tui.Button) { u.showQC() })
	hb := tui.NewHBox(u.sidebar, u.wrkArea)
	u.status = tui.NewStatusBar("Listo.")
	u.box = tui.NewVBox(hb, u.status)

	return
}

func (u *UI) Run() (e error) {
	e = u.tu.Run()
	return
}

func (u *UI) showUsrQC() {
	u.wrkArea.Remove(0)
	ue, bt, lb := tui.NewEntry(), tui.NewButton("[Obtener]"),
		tui.NewLabel("Cuota y consumo del usuario introducido")
	bt.OnActivated(func(b *tui.Button) {
		q, e := http.NewRequest(http.MethodPost,
			u.proxyAddr+UserStatus,
			bytes.NewBufferString(ue.Text()))
		var r *http.Response
		if e == nil {
			q.Header.Set(AuthHd, u.scrt)
			r, e = http.DefaultClient.Do(q)
		}
		var bs []byte
		if e == nil {
			bs, e = ioutil.ReadAll(r.Body)
		}
		var qc *QtCs
		if e == nil {
			qc = new(QtCs)
			e = json.Unmarshal(bs, qc)
		}
		if e == nil {
			lb.SetText(fmt.Sprintf("Cuota: %s Consumo: %s",
				datasize.ByteSize(qc.Quota).HumanReadable(),
				datasize.ByteSize(qc.Consumption).HumanReadable()))
		} else {
			lb.SetText(string(bs))
		}
	})
	tui.DefaultFocusChain.Set(ue, bt, u.sessB, u.qcB, u.qcuB)
	ue.SetFocused(true)
	bx := tui.NewVBox(ue, bt, lb)
	u.wrkArea.Append(bx)
}

func (u *UI) showLoginBox() {
	u.wrkArea.Remove(0)

	u.user.SetFocused(true)

	u.pass.SetEchoMode(tui.EchoModePassword)

	form := tui.NewGrid(0, 0)
	form.AppendRow(
		tui.NewLabel("Usuario"),
		tui.NewLabel("Contraseña"),
	)
	form.AppendRow(u.user, u.pass)
	form.AppendRow(u.proxy)

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

	if u.qcuB != nil {
		tui.DefaultFocusChain.Set(u.user, u.pass, u.proxy, login, logout,
			u.qcB, u.qcuB, u.sessB)
	} else {
		tui.DefaultFocusChain.Set(u.user, u.pass, u.proxy, login, logout,
			u.qcB, u.sessB)
	}

	tui.DefaultFocusChain.FocusNext(u.sessB)
	u.wrkArea.Append(window)
}

func (u *UI) showQC() {
	u.wrkArea.Remove(0)
	cons, e := get(u.proxyAddr, UserStatus, u.scrt)
	var qc *QtCs
	if e == nil {
		qc = new(QtCs)
		e = json.Unmarshal(cons, qc)
	}
	var msg string
	if e == nil {
		qt, cs := datasize.ByteSize(qc.Quota),
			datasize.ByteSize(qc.Consumption)
		msg = fmt.Sprintf("Cuota: %s Consumo: %s",
			qt.HumanReadable(), cs.HumanReadable())

	} else if len(cons) == 0 {
		msg = e.Error()
	} else {
		msg = string(cons)
	}
	lb := tui.NewLabel(msg)
	u.wrkArea.Append(lb)
}

func (u *UI) login() {
	cr := &credentials{u.user.Text(), u.pass.Text()}
	bs, e := json.Marshal(&cr)
	var r *http.Response
	if e == nil {
		r, e = http.Post(u.proxy.Text()+LogX, "text/json",
			bytes.NewReader(bs))
	}
	if e == nil {
		bs, e = ioutil.ReadAll(r.Body)
		r.Body.Close()
	}
	var lr *LogRs
	if e == nil {
		lr = new(LogRs)
		e = json.Unmarshal(bs, lr)
	}
	if e == nil {
		u.conf.User, u.conf.Pass, u.conf.ProxyAddr = u.user.Text(),
			u.pass.Text(),
			u.proxy.Text()
		u.scrt = lr.Scrt
		u.status.SetText("Sesión abierta.")
		bs, e := yaml.Marshal(u.conf)
		if e == nil {
			fl, e := os.Create(UConfName)
			if e == nil {
				fl.Write(bs)
				fl.Close()
			}
		}
	} else {
		u.status.SetText(string(bs))
	}
}

func (u *UI) logout() {
	q, e := http.NewRequest(http.MethodDelete,
		u.proxyAddr+LogX, nil)
	var r *http.Response
	if e == nil {
		q.Header.Set(AuthHd, u.scrt)
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
		q.Header.Set(AuthHd, hd)
		p, e = http.DefaultClient.Do(q)
	}
	if e == nil {
		bs, e = ioutil.ReadAll(p.Body)
	}
	return
}
