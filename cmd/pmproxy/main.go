package main

import (
	"crypto/tls"
	"flag"
	"github.com/lamg/pmproxy"
	"github.com/lamg/proxy"
	"log"
	h "net/http"
	"os"
	"time"
)

func main() {
	var conf, cert, key, prxAddr string
	var rdt, wrt time.Duration
	flag.StringVar(&conf, "c", "", "Configuration file")
	flag.StringVar(&cert, "r", "", "Cert file for HTTPS server")
	flag.StringVar(&key, "k", "", "Key file for HTTPS server")
	flag.Parse()
	fl, e := os.Open(conf)
	var pctl *pmproxy.ProxyCtl
	if e == nil {
		pctl, e = pmproxy.NewProxyCtl(fl)
	}
	if e == nil {
		fl.Close()
		// Setting timeouts according
		// https://blog.cloudflare.com/
		// the-complete-guide-to-golang-net-http-timeouts/
		api := &h.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  0,
			Addr:         ":443",
			Handler:      pctl,
			TLSNextProto: make(map[string]func(*h.Server, *tls.Conn,
				h.Handler)),
		}
		go api.ListenAndServeTLS(cert, key)
		tr := &h.Transport{
			DialContext:           pctl.PrxFls.DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		ph := &proxy.Proxy{
			Rt:          tr,
			DialContext: pctl.PrxFls.DialContext,
			AddCtxValue: pctl.PrxFls.AddCtxValue,
		}
		prx := &h.Server{
			ReadTimeout:  rdt,
			WriteTimeout: wrt,
			IdleTimeout:  0,
			Addr:         prxAddr,
			Handler:      ph,
			// Disable HTTP/2.
			TLSNextProto: make(map[string]func(*h.Server, *tls.Conn,
				h.Handler)),
		}

		e = prx.ListenAndServe()
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
