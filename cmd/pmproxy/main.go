package main

import (
	"crypto/tls"
	"flag"
	"log"
	h "net/http"

	"github.com/lamg/clock"
	"github.com/spf13/afero"

	"github.com/lamg/pmproxy"
	"github.com/lamg/proxy"
)

func main() {
	var stateFl string
	flag.StringVar(&stateFl, "c", "", "State file")
	flag.Parse()
	ce := make(chan error)
	state, e := pmproxy.NewStateMng(stateFl, afero.NewOsFs())
	// load state
	// configure web interface
	cnt := &pmproxy.Connector{
		Cl: new(clock.OSClock),
		Dl: &pmproxy.OSDialer{
			Timeout: state.ProxyReadTimeout,
		},
		Rd: state.MainDet,
	}
	tr := &h.Transport{
		DialContext: cnt.DialContext,
		Proxy:       cnt.Proxy,
	}
	proxy := &proxy.Proxy{Tr: tr}
	// configure proxy
	web := state.WebInterface()
	srvWeb := &h.Server{
		Addr:         state.WebAddr,
		ReadTimeout:  state.WebReadTimeout,
		WriteTimeout: state.WebWriteTimeout,
		Handler:      web,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*h.Server, *tls.Conn, h.Handler)),
	}
	go func() {
		e := srvWeb.ListenAndServeTLS(state.CertFile, state.KeyFile)
		ce <- e
	}()
	// launch web interface
	srvProxy := &h.Server{
		Addr:         state.ProxyAddr,
		ReadTimeout:  state.ProxyReadTimeout,
		WriteTimeout: state.ProxyWriteTimeout,
		Handler:      proxy,
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*h.Server, *tls.Conn, h.Handler)),
	}
	go func() {
		e := srvProxy.ListenAndServe()
		ce <- e
	}()
	// launch proxy
	for e == nil {
		e = <-ce
	}
	if e != nil {
		log.Fatal(e.Error())
	}
	// handle errors
}
