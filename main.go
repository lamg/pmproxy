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
	flag.Parse()
	var pr *proxy.ProxyHttpServer
	pr = goproxy.NewProxyHttpServer()
	pr.OnRequest().DoFunc(loginHandler)
	pr.OnRequest().DoFunc(quotaHandler)
	pr.OnRequest().DoFunc(logoutHandler)
	pr.Verbose = *vb
	log.Fatal(http.ListenAndServe(*addr, proxy))
}

func loginHandler(req *http.Request, ctx *proxy.ProxyCtx) {

}

func quotaHandler(req *http.Request, ctx *proxy.ProxyCtx) {
}

func logoutHandler(req *http.Request, ctx *proxy.ProxyCtx) {
}
