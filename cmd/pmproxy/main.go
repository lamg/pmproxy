package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	h "net/http"

	fs "github.com/lamg/filesystem"
	"github.com/lamg/pmproxy"
)

func main() {
	var conf string
	var dAuth bool
	flag.BoolVar(&dAuth, "d", false,
		"Use dummy authentication instad of LDAP")
	flag.StringVar(&conf, "c", "", "Configuration file")
	flag.Parse()
	os := &fs.OSFS{}
	f, e := os.Open(conf)
	var c *pmproxy.Conf
	if e == nil {
		c, e = pmproxy.ParseConf(f)
	}
	var lh, pm h.Handler
	if e == nil {
		pm, lh, e = pmproxy.ConfPMProxy(c, dAuth, os)
	}
	if e == nil {
		// Setting timeouts according
		// https://blog.cloudflare.com/
		// the-complete-guide-to-golang-net-http-timeouts/
		webUI := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  0,
			Addr:         c.UISrvAddr,
			Handler:      lh,
		}
		go webUI.ListenAndServeTLS(c.CertFl, c.KeyFl)
		proxy := &http.Server{
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  0,
			Addr:         c.ProxySrvAddr,
			Handler:      pm,
		}

		e = proxy.ListenAndServe()
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
