package pmproxy

import (
	"crypto/tls"
	fh "github.com/valyala/fasthttp"
	h "net/http"
)

// Serve starts the control interface and proxy servers,
// according parameters in configuration
func Serve() (e error) {
	var c *conf
	var hcs []*handlerConf
	fs := []func(){
		func() { c, e = newConf() },
		func() { hcs, e = newHnds(c) },
		func() {
			fes := make([]func() error, len(hcs))
			forall(
				func(i int) {
					fes[i] = serveFunc(c, hcs[i])
				},
				len(fes),
			)
			e = runConcurr(fes)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func serveFunc(cf *conf, hc *handlerConf) (fe func() error) {
	var listenAndServe func() error
	var listenAndServeTLS func(string, string) error
	c := hc.sc
	srvChs := []choice{
		{
			guard: func() bool { return c.fastOrStd },
			runf: func() (e error) {
				fast := &fh.Server{
					ReadTimeout:        c.readTimeout,
					WriteTimeout:       c.writeTimeout,
					Handler:            hc.sh.reqHnd,
					MaxConnsPerIP:      c.maxConnIP,
					MaxRequestsPerConn: c.maxReqConn,
				}
				listenAndServe = func() error {
					return fast.ListenAndServe(c.addr)
				}
				listenAndServeTLS = func(cert, key string) (e error) {
					return fast.ListenAndServeTLS(c.addr, cert, key)
				}
				return
			},
		},
		{
			guard: func() bool { return !c.fastOrStd },
			runf: func() (e error) {
				std := &h.Server{
					ReadTimeout:  c.readTimeout,
					WriteTimeout: c.writeTimeout,
					IdleTimeout:  0,
					Addr:         c.addr,
					Handler:      hc.sh.serveHTTP,
					TLSNextProto: make(map[string]func(*h.Server,
						*tls.Conn, h.Handler)),
				}
				listenAndServe = std.ListenAndServe
				listenAndServeTLS = std.ListenAndServeTLS
				return
			},
		},
	}
	ifacePrx := []choice{
		{
			guard: func() bool { return c.proxyOrIface },
			runf: func() (e error) {
				fe = listenAndServe
				return
			},
		},
		{
			guard: func() bool { return !c.proxyOrIface },
			runf: func() (e error) {
				fe = func() error {
					cert, key := cf.configPath(c.certFl),
						cf.configPath(c.keyFl)
					return listenAndServeTLS(cert, key)
				}
				return
			},
		},
	}
	chs := [][]choice{srvChs, ifacePrx}
	inf := func(i int) {
		runChoice(chs[i])
	}
	forall(inf, len(chs))
	return
}
