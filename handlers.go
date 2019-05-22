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
	"encoding/json"
	"github.com/AdhityaRamadhanus/fasthttpcors"
	"github.com/lamg/algorithms"
	"github.com/lamg/proxy"
	"github.com/rs/cors"
	fh "github.com/valyala/fasthttp"
	"io/ioutil"
	"net"
	h "net/http"
	"path"
	"time"
)

type srvHandler struct {
	ServeHTTP h.HandlerFunc
	ReqHnd    fh.RequestHandler
}

func newHnds(prx, iface *srvConf) (prh, ifh *srvHandler) {
	prh, ifh = new(srvHandler), new(srvHandler)
	if prx.fast != nil {
		prh.ReqHnd = proxy.NewFastProxy(prx.ctl, prx.dialTimeout,
			prx.now)
	} else {
		prh.ServeHTTP = proxy.NewProxy(prx.ctl, prx.dialTimeout,
			prx.std.maxIdle, prx.std.idleT, prx.std.tlsHT,
			prx.std.expCT, prx.now).ServeHTTP
	}
	if iface.fast != nil {
		fhnd := fastIface(iface.staticFPath, iface.cmdChan)
		cropt := fasthttpcors.DefaultHandler()
		ifh.ReqHnd = cropt.CorsMiddleware(fhnd)
	} else {
		shnd := stdIface(iface.staticFPath, iface.cmdChan)
		cropt := cors.AllowAll()
		ifh.ServeHTTP = cropt.Handler(shnd).ServeHTTP
	}
	return
}

func fastIface(staticFPath string,
	mng func(*Cmd)) (hnd fh.RequestHandler) {
	hnd = func(ctx *fh.RequestCtx) {
		fs := &fh.FS{
			Root: staticFPath,
		}
		fsHnd := fs.NewRequestHandler()
		compatibleIface(
			mng,
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
			func(err string) {
				ctx.Response.SetStatusCode(h.StatusBadRequest)
				ctx.Response.SetBodyString(err)
			},
		)
	}
	return
}

func stdIface(staticFPath string, mng func(*Cmd)) (hnd h.HandlerFunc) {
	hnd = func(w h.ResponseWriter, r *h.Request) {
		compatibleIface(
			mng,
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
			func(err string) {
				h.Error(w, err, h.StatusBadRequest)
			},
		)
	}
	return
}

func compatibleIface(mng func(*Cmd), path, method,
	rAddr string, body func() ([]byte, error),
	resp func([]byte), fileSrv, writeErr func(string)) {
	m := new(Cmd)
	var e error
	var bs []byte
	fs := []func(){
		func() {
			bs, e = body()
		},
		func() {
			if path == ApiCmd && method == h.MethodPost {
				e = json.Unmarshal(bs, m)
			} else {
				path = emptyPathIfLogin(path)
				fileSrv(path)
				m = &Cmd{Cmd: skip, Manager: ResourcesK}
			}
		},
		func() {
			m.IP, _, e = net.SplitHostPort(rAddr)
		},
		func() { mng(m); e = m.e },
		func() {
			if m.bs != nil {
				resp(m.bs)
			}
		},
	}
	if !alg.TrueFF(fs, func() bool { return e == nil }) {
		writeErr(e.Error())
	}
}

func emptyPathIfLogin(pth string) (r string) {
	r = pth
	if pth == loginPref || pth == loginPrefSlash {
		r = ""
	}
	return
}
