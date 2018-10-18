package main

import (
	"log"
	"os"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

func main() {
	ap, e := gtk.ApplicationNew("com.github.lamg.pmuser-gtk",
		glib.APPLICATION_FLAGS_NONE)
	if e == nil {
		ap.Connect("activate", activate)
		glib.SetApplicationName("PMProxy manager")
		r := ap.Run(os.Args)
		os.Exit(r)
	} else {
		log.Fatal(e.Error())
	}
}

func activate(a *gtk.Application) {
	e := initW(a)
	if e != nil {
		log.Print(e.Error())
	}
}
