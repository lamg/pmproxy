package main

import (
	"flag"
	"github.com/lamg/errors"
	fs "github.com/lamg/filesystem"
	"github.com/lamg/pmproxy"
	"log"
	"net/http"
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
		// FIXME *errors.Error and error interaction doubt
		c, e = pmproxy.ParseConf(f)
	}
	var lh *pmproxy.LocalHn
	var pm *pmproxy.PMProxy
	if e == nil {
		var ec *errors.Error
		pm, lh, ec = pmproxy.ConfPMProxy(c, dAuth, os)
		if ec != nil {
			e = ec.Err
		}
	}
	if e == nil {
		go http.ListenAndServeTLS(c.UISrvAddr, c.CertFl, c.KeyFl,
			lh)
		e = http.ListenAndServe(c.ProxySrvAddr, pm)
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
