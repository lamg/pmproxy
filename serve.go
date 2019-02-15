package pmproxy

import (
	fh "github.com/valyala/fasthttp"
	h "net/http"
)

// Serve starts the control interface and proxy servers,
// according parameters in configuration
func Serve() (e error) {
	c := newConf()
	hcs, e := newHnds(c)
	if e == nil {
		fes := make([]func() error, len(hcs))
		forall(func(i int) {
			fes[i] = serveFunc(c, hcs[i].sc, hcs[i].sh)
		},
			len(fes),
		)
		e = runConcurr(fes)
	}
	return
}

func serveFunc(cf *conf, c *srvConf,
	sh *srvHandler) (fe func() error) {
	var listenAndServe func() error
	var listenAndServeTLS func(string, string) error
	srvChs := []choice{
		{
			guard: func() bool { return c.fastOrStd },
			runf: func() (e error) {
				fast = &fh.Server{
					ReadTimeout:        c.readTimeout,
					WriteTimeout:       c.writeTimeout,
					Addr:               c.addr,
					Handler:            sh.reqHnd,
					MaxConnsPerIP:      c.maxConnIP,
					MaxRequestsPerConn: c.maxReqConn,
				}
				listenAndServe = fast.ListenAndServe
				listenAndServeTLS = fast.ListenAndServeTLS
				return
			},
		},
		{
			guard: func() bool { return !c.fastOrStd },
			runf: func() (e error) {
				std = &h.Server{
					ReadTimeout:  c.readTimeout,
					WriteTimeout: c.writeTimeout,
					IdleTimeout:  0,
					Addr:         c.addr,
					Handler:      sh.serveHTTP,
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
