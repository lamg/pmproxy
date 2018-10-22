package main

import (
	"github.com/rivo/tview"
)

func main() {
	u := newUI()
	e := tview.NewApplication().SetRoot(u.grid, true).Run()
	if e != nil {
		panic(e)
	}
}

type ui struct {
	grid *tview.Grid
}

func newUI() (u *ui) {
	u = new(ui)
	pages := tview.NewList().
		ShowSecondaryText(false).
		AddItem("Login", "", 0, u.showLogin)
	pages.SetBorder(true)
	u.grid = tview.NewGrid()
	u.grid.SetRows(0, 0)
	u.grid.SetColumns(0, 0)
	u.grid.AddItem(pages, 0, 0, 2, 1, 2, 2, true)
	return
}

func box(caption string) (p *tview.TextView) {
	p = tview.NewTextView()
	p.SetTextAlign(tview.AlignCenter)
	p.SetText(caption)
	return
}

func (u *ui) showLogin() {
	u.grid.AddItem(box(logo), 0, 1, 1, 1, 2, 2, false)
	u.grid.AddItem(loginBox(new(loginState)), 1, 1, 1, 1, 2, 2, true)
}
