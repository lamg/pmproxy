package pmproxy

import (
	"github.com/lamg/proxy"
	fh "github.com/valyala/fasthttp"
	"io"
	"net"
	h "net/http"
	"path"
)

// Serve starts the control interface and proxy servers,
// according parameters in configuration
func Serve() (e error) {
	hcs, e := newHnds()
	if e == nil {
		fes := make([]func() error, len(hcs))
		forall(func(i int) {
			fes[i] = serveFunc(hcs[i].sc, hcs[i].sh)
		},
			len(fes),
		)
		e = runConcurr(fes)
	}
	return
}

func serveFunc(c *srvConf,
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
					cert, key := configPath(c.certFl),
						configPath(c.keyFl)
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

func configPath(file string) (fpath string) {
	cfl := viper.ConfigFileUsed()
	fpath = path.Join(path.Dir(cfl), file)
	return
}
