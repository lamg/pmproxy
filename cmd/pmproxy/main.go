package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lamg/errors"
	fs "github.com/lamg/filesystem"
	"github.com/lamg/pmproxy"
	"golang.org/x/crypto/acme/autocert"
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
		var ec *errors.Error
		c, ec = pmproxy.ParseConf(f)
		if ec != nil {
			e = ec.Err
		}
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
		hostPolicy := func(ctx context.Context,
			host string) (e error) {
			if host != c.HostName {
				e = fmt.Errorf(
					"acme/autocert: only %s host is allowed",
					c.HostName)
			}
			return
		}
		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: hostPolicy,
			Cache:      autocert.DirCache(c.DataDir),
		}
		// Setting timeouts according
		// https://blog.cloudflare.com/
		// the-complete-guide-to-golang-net-http-timeouts/
		webUI := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			Addr:         c.UISrvAddr,
			Handler:      lh,
			TLSConfig: &tls.Config{
				GetCertificate: m.GetCertificate,
			},
		}
		go webUI.ListenAndServeTLS("", "")
		proxy := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
			Addr:         c.ProxySrvAddr,
			Handler:      pm,
		}

		e = proxy.ListenAndServe()
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
