package main

import(
	"github.com/lamg/pmproxy"
	"github.com/lamg/proxy"
	"flag"
	"os"
	h "net/http"
)

func main() {
	var conf, cert, key string
	flag.StringVar(&conf, "c", "", "Configuration file")
	flag.StringVar(&cert, "r", "", "Cert file for HTTPS server")
	flag.StringVar(&key, "k", "", "Key file for HTTPS server")
	flag.Parse()
	fl, e := os.Open(conf)
	var pctl *pmproxy.ProxyCtl
	if e == nil {
		pctl, e = pmproxy.NewProxyCtl(fl)	
	}
	if e == nil{
		fl.Close()
		// Setting timeouts according
		// https://blog.cloudflare.com/
		// the-complete-guide-to-golang-net-http-timeouts/
		api := &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  0,
			Addr:         ":443",
			Handler:      pctl,
			TLSNextProto: make(map[string]func(*h.Server, *tls.Conn,
				h.Handler)),
		}
		go api.ListenAndServeTLS(cert, key)
	}
	
}
