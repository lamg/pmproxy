package main

import (
	"github.com/rivo/tview"
)

func main() {
	initUI()
}

func initUI() {
	grid := tview.NewGrid()
	grid.SetRows(0, 0)
	grid.SetColumns(0, 0)
	grid.AddItem(box("Hola"), 0, 0, 1, 1, 2, 2, false)
	grid.AddItem(box("Mundo"), 0, 1, 1, 1, 2, 2, false)
	grid.AddItem(box("2"), 1, 0, 1, 1, 2, 2, false)
	grid.AddItem(box("3"), 1, 1, 1, 1, 2, 2, true)
	e := tview.NewApplication().SetRoot(grid, true).Run()
	if e != nil {
		panic(e)
	}
}

func box(caption string) (p *tview.TextView) {
	p = tview.NewTextView()
	p.SetTextAlign(tview.AlignCenter)
	p.SetText(caption)
	return
}
