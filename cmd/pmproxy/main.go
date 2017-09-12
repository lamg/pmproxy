package main

import (
	"flag"
	"github.com/elazarl/goproxy"
	"github.com/lamg/pmproxy"
	"log"
	"net/http"
)

// TODO serve PMProxy.ServeHTTP

func main() {
	var addr string
	flag.StringVar(&addr, ":8080", "Proxy listen address")
	// Serve in addr

}
