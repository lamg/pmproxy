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

func loginBox() (b *tview.Form) {
	b = tview.NewForm()
	b.SetBorder(true)
	b.AddInputField("User", "", 0, nil, nil)
	b.AddPasswordField("Password", "blablabla", 0, '●', nil)
	b.AddInputField("Proxy address", "", 0, nil, nil)
	return
}
