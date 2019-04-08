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
	"github.com/lamg/proxy"
	fh "github.com/valyala/fasthttp"
	"io/ioutil"
	"net"
	h "net/http"
	"path"
	"strings"
	"time"
)

type handlerConf struct {
	sh *srvHandler
	sc *srvConf
}

func newHnds(c *conf) (prh, ifh *srvHandler,
	e error) {
	prh, ifh = new(srvHandler), new(srvHandler)
	if c.proxy.fastOrStd {
		// consumers, matchers determine context values
		// dialer and proxy process context values
		prh.reqHnd = proxy.NewFastProxy(c.cm.set,
			c.cm.params, c.cm.apply, c.cm.dialTimeout, time.Now)
	} else {
		prh.serveHTTP = proxy.NewProxy(c.cm.set,
			c.cm.params, c.cm.apply, c.cm.dialTimeout, c.cm.maxIdle,
			c.cm.idleT, c.cm.tlsHT, c.cm.expCT,
			time.Now).ServeHTTP
	}
	if c.iface.fastOrStd {
		// administration, and serializer are part of the
		// control interface, and also have consumers and
		// matchers
		ifh.reqHnd = fastIface(c)
	} else {
		ifh.serveHTTP = stdIface(c)
	}
	return
}

func fastIface(cf *conf) (hnd fh.RequestHandler) {
	hnd = func(ctx *fh.RequestCtx) {
		fs := &fh.FS{
			Root: cf.staticFPath,
		}
		fsHnd := fs.NewRequestHandler()
		compatibleIface(
			cf,
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

func stdIface(cf *conf) (hnd h.HandlerFunc) {
	hnd = func(w h.ResponseWriter, r *h.Request) {
		compatibleIface(
			cf,
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
				pth := path.Join(cf.staticFPath, file)
				h.ServeFile(w, r, pth)
			},
			func(err string) {
				h.Error(w, err, h.StatusBadRequest)
			},
		)
	}
	return
}

func compatibleIface(cf *conf, path, method,
	rAddr string, body func() ([]byte, error),
	resp func([]byte), fileSrv, writeErr func(string)) {
	m := new(cmd)
	var e error
	var bs []byte
	fs := []func(){
		func() {
			bs, e = body()
		},
		func() {
			if path == apiCmd && method == h.MethodPost {
				e = json.Unmarshal(bs, m)
			} else {
				path = emptyPathIfLogin(path)
				fileSrv(path)
				m = &cmd{Cmd: skip, Manager: resourcesK}
			}
		},
		func() {
			m.RemoteAddr, _, e = net.SplitHostPort(rAddr)
		},
		func() { cf.res.manager(m); e = m.e },
		func() {
			if m.bs != nil {
				resp(m.bs)
			}
		},
	}
	if !trueFF(fs, func() bool { return e == nil }) {
		writeErr(e.Error())
	}
}

func compatibleCmd(cf *conf, pth, meth string,
	body []byte, fileSrv func(string)) (c *cmd,
	e error) {
	c = &cmd{
		comp02: true,
	}

	kf := []kFunc{
		{
			apiAuth + h.MethodPost,
			func() {
				c.Cmd = open
				c.Manager = defaultSessionIPM
				c.Cred = new(credentials)
				e = json.Unmarshal(body, c.Cred)
			},
		},
		{
			apiAuth + h.MethodDelete,
			func() {
				c.Cmd = clöse
				c.Manager = defaultSessionIPM
			},
		},
		{
			apiUserStatus + h.MethodGet,
			func() {
				c.Cmd = get
				c.Manager = defaultDwnConsR
			},
		},
		{
			apiUserStatus + h.MethodPut,
			func() {
				c.Cmd = set
				c.Manager = defaultDwnConsR
				nv := &struct {
					Name  string `json: "name"`
					Value uint64 `json: "value"`
				}{}
				e = json.Unmarshal(body, nv)
				if e == nil {
					c.String = nv.Name
					c.Uint64 = nv.Value
				}
			},
		},
		{
			apiCheckUser + h.MethodGet,
			func() {
				c.Cmd = check
				c.Manager = defaultSessionIPM
			},
		},
		{
			apiUserInfo + h.MethodGet,
			func() {
				c.Cmd = get
				c.Manager = defaultUserDB + infoK
			},
		},
	}
	if e == nil && c.comp02 {
		if strings.HasPrefix(pth, apiPref) {
			exF(kf, pth+meth, func(d error) { e = d })
		} else {
			pth = emptyPathIfLogin(pth)
			fileSrv(pth)
			c.Cmd = skip
		}
	}
	return
}

func emptyPathIfLogin(pth string) (r string) {
	r = pth
	if pth == loginPref || pth == loginPrefSlash {
		r = ""
	}
	return
}

type srvHandler struct {
	serveHTTP h.HandlerFunc
	reqHnd    fh.RequestHandler
}

type srvConf struct {
	name         string
	proxyOrIface bool
	fastOrStd    bool
	readTimeout  time.Duration
	writeTimeout time.Duration
	addr         string
	certFl       string
	keyFl        string

	// fasthttp specific
	maxConnIP  int
	maxReqConn int
}

func readSrvConf(i interface{}) (sc *srvConf, e error) {
	sc = new(srvConf)
	fe := func(d error) {
		if d != nil {
			s := d.Error()
			me := noKey(maxConnIPK).Error()
			re := noKey(maxReqConnK).Error()
			if s == me || s == re {
				d = nil
			}
		}
		e = d
	}
	kf := []kFuncI{
		{
			fastOrStdK,
			func(i interface{}) {
				sc.fastOrStd = boolE(i, fe)
			},
		},
		{
			readTimeoutK,
			func(i interface{}) {
				sc.readTimeout = durationE(i, fe)
			},
		},
		{
			writeTimeoutK,
			func(i interface{}) {
				sc.writeTimeout = durationE(i, fe)
			},
		},
		{
			addrK,
			func(i interface{}) {
				sc.addr = stringE(i, fe)
			},
		},
		{
			certK,
			func(i interface{}) {
				sc.certFl = stringE(i, fe)
			},
		},
		{
			keyK,
			func(i interface{}) {
				sc.keyFl = stringE(i, fe)
			},
		},
		{
			maxConnIPK,
			func(i interface{}) {
				sc.maxConnIP = intE(i, fe)
			},
		},
		{
			maxReqConnK,
			func(i interface{}) {
				sc.maxReqConn = intE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (p *srvConf) toMap() (i interface{}) {
	i = map[string]interface{}{
		fastOrStdK:    p.fastOrStd,
		readTimeoutK:  p.readTimeout.String(),
		writeTimeoutK: p.writeTimeout.String(),
		addrK:         p.addr,
		certK:         p.certFl,
		keyK:          p.keyFl,
		maxConnIPK:    p.maxConnIP,
		maxReqConnK:   p.maxReqConn,
	}
	return
}
