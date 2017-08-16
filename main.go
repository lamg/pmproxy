//TODO implement proxy
package main

import (
	"flag"
	proxy "github.com/elazarl/goproxy"
	"log"
	"net/http"
)

func main() {
	var vb *bool
	var addr *string
	vb = flag.Bool("v", false, "Log request to stdout")
	addr = flag.String("addr", ":8080", "proxy listen address")
	// TODO serve login page in another port (80 for production)
	flag.Parse()
	var pr *proxy.ProxyHttpServer
	pr = proxy.NewProxyHttpServer()
	pr.OnRequest().DoFunc(collector)
	pr.Verbose = *vb
	log.Fatal(http.ListenAndServe(*addr, pr))
	//use HijackConnect ?
	//goproxy-stats example
}

func collector(req *http.Request,
	ctx *proxy.ProxyCtx) (r *http.Request, p *http.Response) {
	println("request made " + req.URL.String())
	//authorize request
	//make request
	//collect response
	//return
	r, p = req, new(http.Response)
	return
}
