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
	var prh, ifh *srvHandler
	fs := []func(){
		func() { c, e = newConf(afero.NewOsFs()) },
		func() { prh, ifh, e = newHnds(c) },
		func() {
			cp := c.configPath()
			fes := []func() error{
				serveFunc(c.proxy, cp, true, prh),
				serveFunc(c.iface, cp, false, ifh),
				func() (e error) {
					for {
						time.Sleep(c.waitUpd)
						c.update()
					}
					return
				},
			}
			e = runConcurr(fes)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func serveFunc(c *srvConf, dir string, proxyOrIface bool,
	sh *srvHandler) (fe func() error) {
	cert := path.Join(dir, c.certFl)
	key := path.Join(dir, c.keyFl)
	var listenAndServe func() error
	var listenAndServeTLS func(string, string) error
	if c.fastOrStd {
		fast := &fh.Server{
			ReadTimeout:        c.readTimeout,
			WriteTimeout:       c.writeTimeout,
			Handler:            sh.reqHnd,
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
			Handler:      sh.serveHTTP,
			TLSNextProto: make(map[string]func(*h.Server,
				*tls.Conn, h.Handler)),
		}
		listenAndServe = std.ListenAndServe
		listenAndServeTLS = std.ListenAndServeTLS
	}
	if proxyOrIface {
		fe = listenAndServe
	} else {
		fe = func() error {
			return listenAndServeTLS(cert, key)
		}
	}
	return
}
