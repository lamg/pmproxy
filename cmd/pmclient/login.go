package main

import (
	"github.com/rivo/tview"
)

var logo = `
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
`

func loginBox(l *loginState) (b *tview.Form) {
	b = tview.NewForm().
		AddInputField("User", "", 0, nil, nil).
		AddPasswordField("Password", "blablabla", 0, '●',
			l.passwordChg).
		AddInputField("Proxy address", "", 0, nil, l.proxyAddrChg).
		AddButton("Login", l.proxyLogin).
		AddButton("Logout", l.proxyLogout)
	b.SetBorder(true)
	return
}

type loginState struct {
	user      string
	password  string
	proxyAddr string
}

func (l *loginState) proxyLogin() {
}

func (l *loginState) proxyLogout() {
}

func (l *loginState) userChg(s string) {
	l.user = s
}

func (l *loginState) passwordChg(s string) {
	l.password = s
}

func (l *loginState) proxyAddrChg(s string) {
	l.proxyAddr = s
}
