package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	var e error
	if len(os.Args) != 1 {
		e = fmt.Errorf("pmproxy doesn't take any" +
			"command line argument. It looks for any " +
			"configuration file, with the following order" +
			"and paths: /etc/pmproxy/conf.toml" +
			"$HOME/.config/pmproxy/conf.toml",
		)
	} else {
		e = pmproxy.Serve()
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
