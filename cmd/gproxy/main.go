package main

import (
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
	"log"
	"os"
)

var config = ".gproxy"

func main() {
	ap, e := gtk.ApplicationNew("com.github.lamg.gproxy",
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
	var e error
	f, _ := os.Open(config)
	e = initW(a, f)
	if e != nil {
		log.Print(e.Error())
	}
}
