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
	"bytes"
	"crypto/tls"
	"encoding/json"
	"github.com/AdhityaRamadhanus/fasthttpcors"
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/lamg/proxy"
	"github.com/rs/cors"
	"github.com/spf13/afero"
	fh "github.com/valyala/fasthttp"
	"io/ioutil"
	"net"
	h "net/http"
	"path"
	"time"
)

// Serve starts the control interface and proxy servers,
// according parameters in configuration
func Serve(fs afero.Fs) (e error) {
	p, e := load(fs)
	var cmdChan mng.CmdF
	var dialer *mng.Dialer
	var persist func() error
	if e == nil {
		cmdChan, dialer, persist, e = mng.Load(confDir, fs)
	}
	if e == nil {
		dialer.Timeout = p.Proxy.DialTimeout
		fes := []func() error{
			func() error { return serveAPI(p.Api, cmdChan) },
			func() error {
				return serveProxy(p.Proxy, dialer.DialContext)
			},
			func() (e error) {
				for {
					time.Sleep(p.Api.PersistInterval)
					persist()
				}
				return
			},
		}
		e = alg.RunConcurr(fes)
	}
	return
}

func serveAPI(i *apiConf, cmdChan mng.CmdF) (e error) {
	if i.Server.FastOrStd {
		fhnd := fastIface(i.WebStaticFilesDir, cmdChan,
			i.ExcludedRoutes)
		cropt := fasthttpcors.DefaultHandler()
		fast := &fh.Server{
			ReadTimeout:  i.Server.ReadTimeout,
			WriteTimeout: i.Server.WriteTimeout,
			Handler:      cropt.CorsMiddleware(fhnd),
		}
		e = fast.ListenAndServeTLS(i.Server.Addr, i.HTTPSCert,
			i.HTTPSKey)
	} else {
		shnd := StdIface(i.WebStaticFilesDir, cmdChan, i.ExcludedRoutes)
		cropt := cors.AllowAll()
		std := &h.Server{
			ReadTimeout:  i.Server.ReadTimeout,
			WriteTimeout: i.Server.WriteTimeout,
			Addr:         i.Server.Addr,
			Handler:      cropt.Handler(shnd),
			TLSNextProto: make(map[string]func(*h.Server,
				*tls.Conn, h.Handler)),
		}
		e = std.ListenAndServeTLS(i.HTTPSCert, i.HTTPSKey)
	}
	return
}

func serveProxy(p *proxyConf, dial proxy.Dialer) (e error) {
	if p.Server.FastOrStd {
		prx := proxy.NewFastProxy(dial)
		fast := &fh.Server{
			ReadTimeout:  p.Server.ReadTimeout,
			WriteTimeout: p.Server.WriteTimeout,
			Handler:      prx.RequestHandler,
		}
		e = fast.ListenAndServe(p.Server.Addr)
	} else {
		std := &h.Server{
			ReadTimeout:  p.Server.ReadTimeout,
			WriteTimeout: p.Server.WriteTimeout,
			Addr:         p.Server.Addr,
			Handler:      proxy.NewProxy(dial),
			// Disable HTTP/2.
			TLSNextProto: make(map[string]func(*h.Server,
				*tls.Conn, h.Handler)),
		}
		e = std.ListenAndServe()
	}
	return
}

func fastIface(staticFPath string,
	cmdChan mng.CmdF, excl []string) (hnd fh.RequestHandler) {
	hnd = func(ctx *fh.RequestCtx) {
		fs := &fh.FS{
			IndexNames:         []string{"index.html"},
			Root:               staticFPath,
			GenerateIndexPages: false,
		}
		fsHnd := fs.NewRequestHandler()
		compatibleIface(
			cmdChan,
			string(ctx.Request.URI().Path()),
			string(ctx.Method()),
			ctx.RemoteAddr().String(),
			func() (bs []byte, e error) {
				buff := new(bytes.Buffer)
				e = ctx.Request.BodyWriteTo(buff)
				bs = buff.Bytes()
				return
			},
			func(bs []byte) {
				ctx.Response.SetBody(bs)
			},
			func(file string) {
				ctx.URI().SetPath(file)
				fsHnd(ctx)
			},
			func(err error) {
				bs, e := json.Marshal(err)
				ctx.Response.SetStatusCode(h.StatusBadRequest)
				if e == nil {
					ctx.Response.SetBody(bs)
				} else {
					ctx.Response.SetBodyString(err.Error())
				}
			},
			excl,
		)
	}
	return
}

func StdIface(staticFPath string,
	cmdChan mng.CmdF, excl []string) (hnd h.HandlerFunc) {
	hnd = func(w h.ResponseWriter, r *h.Request) {
		compatibleIface(
			cmdChan,
			r.URL.Path,
			r.Method,
			r.RemoteAddr,
			func() (bs []byte, e error) {
				bs, e = ioutil.ReadAll(r.Body)
				r.Body.Close()
				return
			},
			func(bs []byte) {
				w.Write(bs)
			},
			func(file string) {
				pth := path.Join(staticFPath, file)
				h.ServeFile(w, r, pth)
			},
			func(err error) {
				bs, e := json.Marshal(err)
				var res string
				if e == nil {
					res = string(bs)
				} else {
					res = err.Error()
				}
				h.Error(w, res, h.StatusBadRequest)
			},
			excl,
		)
	}
	return
}

const (
	ApiCmd = "/api/cmd"
)

func compatibleIface(cmdChan mng.CmdF, path, method,
	rAddr string, body func() ([]byte, error),
	resp func([]byte), fileSrv func(string), writeErr func(error),
	excl []string,
) {
	m := new(mng.Cmd)
	var e error
	var bs, data []byte
	var ip string
	fs := []func(){
		func() {
			bs, e = body()
		},
		func() {
			if path == ApiCmd && method == h.MethodPost {
				e = json.Unmarshal(bs, m)
			} else {
				ib := func(i int) bool {
					return path == excl[i] || path == excl[i]+"/"
				}
				ok, _ := alg.BLnSrch(ib, len(excl))
				if ok {
					path = ""
				}
				fileSrv(path)
				m = &mng.Cmd{Manager: mng.Skip}
			}
		},
		func() {
			ip, _, e = net.SplitHostPort(rAddr)
		},
		func() { data, e = cmdChan(m, ip) },
		func() {
			if data != nil {
				resp(data)
			}
		},
	}
	if !alg.TrueFF(fs, func() bool { return e == nil }) {
		writeErr(e)
	}
}
