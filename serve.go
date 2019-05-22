// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	"crypto/tls"
	"github.com/spf13/afero"
	fh "github.com/valyala/fasthttp"
	h "net/http"
	"path"
	"time"
)

// Serve starts the control interface and proxy servers,
// according parameters in configuration
func Serve() (e error) {
	var c *conf
	var prx, iface *srvConf
	fs := []func(){
		func() { prx, iface, e = loadSrvConf(afero.NewOsFs()) },
		func() {
			prh, ifh := newHnds(prx, iface)
			fes := []func() error{
				serveFunc(prx, prh),
				serveFunc(iface, ifh),
				func() (e error) {
					for {
						time.Sleep(iface.iface.persistIntv)
						iface.iface.persist()
					}
					return
				},
			}
			e = alg.RunConcurr(fes)
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
	return
}

func serveFunc(c *srvConf, sh *srvHandler) (fe func() error) {
	var listenAndServe func() error
	var listenAndServeTLS func(string, string) error
	if sh.ReqHnd != nil {
		fast := &fh.Server{
			ReadTimeout:        c.readTimeout,
			WriteTimeout:       c.writeTimeout,
			Handler:            sh.ReqHnd,
			MaxConnsPerIP:      c.maxConnIP,
			MaxRequestsPerConn: c.maxReqConn,
		}
		listenAndServe = func() error {
			return fast.ListenAndServe(c.addr)
		}
		listenAndServeTLS = func(cert,
			key string) (e error) {
			return fast.ListenAndServeTLS(c.addr, cert, key)
		}
	} else {
		std := &h.Server{
			ReadTimeout:  c.readTimeout,
			WriteTimeout: c.writeTimeout,
			IdleTimeout:  0,
			Addr:         c.addr,
			Handler:      sh.ServeHTTP,
			TLSNextProto: make(map[string]func(*h.Server,
				*tls.Conn, h.Handler)),
		}
		listenAndServe = std.ListenAndServe
		listenAndServeTLS = std.ListenAndServeTLS
	}
	if c.prx != nil {
		fe = listenAndServe
	} else {
		fe = func() error {
			return listenAndServeTLS(c.iface.certFl, c.iface.keyFl)
		}
	}
	return
}
