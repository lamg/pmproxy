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

func newHnds(c *conf) (hs []*handlerConf, e error) {
	var sl []interface{}
	fs := []func(){
		func() {
			sl, e = c.sliceE(srvConfK)
		},
		func() {
			if len(sl) != 2 {
				e = needXServers(2, len(sl))
			}
		},
		func() {
			hs = make([]*handlerConf, len(sl))
			ib := func(i int) (b bool) {
				hs[i], e = readSrvConf(sl[i])
				b = e == nil
				return
			}
			trueForall(ib, len(sl))
		},
		func() {
			readHnd(hs, c)
			forall(func(i int) {
				c.mappers.Store(hs[i].sc.name, hs[i].sc.toMap)
			}, len(hs))
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func readHnd(hcs []*handlerConf, c *conf) {
	inf := func(i int) {
		if hcs[i].sc.proxyOrIface {
			// consumers, matchers determine context values
			// dialer and proxy process context values
			if hcs[i].sc.fastOrStd {
				hcs[i].sh.reqHnd = proxy.NewFastProxy(c.cm.direct,
					c.cm.ctxVal, c.cm.proxyF, time.Now)
			} else {
				hcs[i].sh.serveHTTP = proxy.NewProxy(c.cm.direct,
					c.cm.ctxVal, c.cm.proxyF, c.cm.maxIdle,
					c.cm.idleT, c.cm.tlsHT, c.cm.expCT,
					time.Now).ServeHTTP
			}
		} else {
			// administration, and serializer are part of the
			// control interface, and also have consumers and
			// matchers
			if hcs[i].sc.fastOrStd {
				hcs[i].sh.reqHnd = fastIface(c)
			} else {
				hcs[i].sh.serveHTTP = stdIface(c)
			}
		}
	}
	forall(inf, len(hcs))
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
			string(ctx.Request.Header.Peek(authHd)),
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
			r.Header.Get(authHd),
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
				h.ServeFile(w, r, path.Join(cf.staticFPath, file))
			},
			func(err string) {
				h.Error(w, err, h.StatusBadRequest)
			},
		)
	}
	return
}

func compatibleIface(cf *conf, path, method, header,
	rAddr string, body func() ([]byte, error),
	resp func([]byte), fileSrv, writeErr func(string)) {
	var m *cmd
	var e error
	var bs []byte
	fs := []func(){
		func() {
			bs, e = body()
		},
		func() {
			m, e = compatibleCmd(cf, path, method, bs, fileSrv)
		},
		func() {
			if !m.comp02 {
				e = json.Unmarshal(bs, m)
			} else {
				m.Secret = header
			}
		},
		func() {
			m.RemoteAddr, _, e = net.SplitHostPort(rAddr)
		},
		func() { cf.manager(m); e = m.e },
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
		comp02: cf.böol(compatible02K),
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
				c.Manager = defaultUserDBInfo
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

func readSrvConf(i interface{}) (h *handlerConf,
	e error) {
	h = &handlerConf{sc: new(srvConf)}
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			proxyOrIfaceK,
			func(i interface{}) {
				h.sc.proxyOrIface = boolE(i, fe)
				if h.sc.proxyOrIface {
					h.sc.name = "proxy"
				} else {
					h.sc.name = "api"
				}
			},
		},
		{
			fastOrStdK,
			func(i interface{}) {
				h.sc.fastOrStd = boolE(i, fe)
			},
		},
		{
			readTimeoutK,
			func(i interface{}) {
				h.sc.readTimeout = durationE(i, fe)
			},
		},
		{
			writeTimeoutK,
			func(i interface{}) {
				h.sc.writeTimeout = durationE(i, fe)
			},
		},
		{
			addrK,
			func(i interface{}) {
				h.sc.addr = stringE(i, fe)
			},
		},
		{
			certK,
			func(i interface{}) {
				h.sc.certFl = stringE(i, fe)
			},
		},
		{
			keyK,
			func(i interface{}) {
				h.sc.keyFl = stringE(i, fe)
			},
		},
		{
			maxConnIPK,
			func(i interface{}) {
				h.sc.maxConnIP = intE(i, fe)
			},
		},
		{
			maxReqConnK,
			func(i interface{}) {
				h.sc.maxReqConn = intE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (p *srvConf) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:         p.name,
		proxyOrIfaceK: p.proxyOrIface,
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
