package pmproxy

import (
	"bytes"
	"encoding/json"
	fh "github.com/valyala/fasthttp"
	h "net/http"
	"time"
)

type handlerConf struct {
	sh   *srvHandler
	sc   *srvConf
	conf []func() interface{}
}

func newHnds(c *conf) (hs []*handlerConf,
	fs []func() interface{}, e error) {
	var sl []interface{}
	var ac *connMng
	fs = []func(){
		func() {
			sl, e = c.sliceE(srvConfK)
		},
		func() {
			if len(sl) != 2 {
				e = needXServers(2, len(sl))
			}
		},
		func() {
			ib := func(i int) (b bool) {
				hs[i], e = readSrvConf(sl[i])
				b = e == nil
				return
			}
			trueForall(ib, len(sl))
		},
		func() {
			ac, e = newConnMng(c)
		},
		func() {
			readHnd(hs, ac, c)
			forall(func(i int) {
				fs = append(fs, hs[i].sc.toStringMap)
			}, len(hs))
			fs = append(fs, ac.confs...)
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
				hcs[i].reqHnd = proxy.NewFastProxy(ac.direct,
					ac.ctxVal, ac.proxyF, time.Now).FastHandler
			} else {
				hcs[i].serveHTTP = proxy.NewProxy(ac.direct,
					ac.ctxVal, ac.proxyF, ac.maxIdle, ac.idleT,
					ac.tlsHT, ac.expCT).ServeHTTP
			}
		} else {
			// administration, and serializer are part of the
			// control interface, and also have consumers and
			// matchers
			comp02 := c.böol(compatible02K)
			staticFPath := c.strïng(staticFilesPathK)
			if hcs[i].sc.fastOrStd {
				hcs[i].reqHnd = fastIface(c, comp02, staticFPath)
			} else {
				hcs[i].serveHTTP = stdIface(c, comp02, staticFPath)
			}
		}
	}
	forall(inf, len(hcs))
	return
}

func fastIface(cf *conf, comp02 bool,
	staticFPath string) (hnd fh.RequestHandler) {
	fs := &fh.FS{
		Root: staticFPath,
	}
	fsHnd := fs.NewRequestHandler()
	hnd = func(ctx *fh.RequestCtx) {
		if comp02 {
			pth := string(ctx.Request.URI().Path)
			meth := string(ctx.Method)
			token := string(ctx.Request.Header.Peek(authHd))
			if strings.HasPrefix(pth, apiPref) {
				cmd, e = compatibleCmd(pth, meth, token)
			} else {
				// serve static files
				pth = emptyPathIfLogin(pth)
				fsHnd(ctx)
				cmd = cmd{
					Cmd: skip,
				}
			}
		}
		buff, cmd := new(bytes.Buffer), new(cmd)
		var e error
		fs := []func(){
			func() { e = ctx.Request.BodyWriteTo(buff) },
			func() { e = json.NewDecoder(buff).Decode(cmd) },
			func() { cf.manager(cmd); e = cmd.e },
			func() {
				if cmd.bs != nil {
					ctx.Response.SetBody(cmd.bs)
				}
			},
		}
		ok := trueFF(fs, func() bool { return e == nil })
		if !ok {
			ctx.Response.SetStatusCode(h.StatusBadRequest)
			ctx.Response.SetBodyString(e.Error())
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

func stdIface(cf *conf, comp02 bool,
	staticFPath string) (hnd h.HandlerFunc) {
	hnd = func(w h.ResponseWriter, r *h.Request) {
		var cmd *cmd
		var e error
		if comp02 {
			pth := r.URL.Path
			if strings.HasPrefix(pth, apiPref) {
				cmd, e = compatibleCmd(pth, r.Method,
					r.Header.Get(authHd))
			} else {
				pth = emptyPathIfLogin(pth)
				// serve static
				h.ServeFile(w, r, path.Join(staticFPath, pth))
				cmd := &cmd{
					Cmd: skip,
				}
			}
		} else {
			cmd = new(cmd)
		}

		fs := []func(){
			func() {
				e = json.NewDecoder(r.Body).Decode(cmd)
			},
			func() { cf.manager(cmd); e = cmd.e },
			func() {
				if cmd.bs != nil {
					_, e = w.Write(cmd.bs)
				}
			},
		}
		ok := trueFF(fs, func() bool { return e == nil })
		if !ok {
			h.Error(w, e.Error())
		}
	}
	return
}

func compatibleCmd(pth, meth, rAddr, hd string) (c *cmd,
	e error) {
	ip, _, e := net.SplitHostPort(rAddr)
	c = &cmd{
		RemoteAddr: ip,
		Secret:     hd,
	}

	kf := []kFunc{
		{
			apiAuth + h.MethodPost,
			func() {
				c.Cmd = open
				c.Adm = defaultSessionIPM
			},
		},
		{
			apiAuth + h.MethodDelete,
			func() {
				c.Cmd = clöse
				c.Adm = defaultSessionIPM
			},
		},
		{
			apiUserStatus + h.MethodGet,
			func() {
				c.Cmd = get
				c.Adm = defaultDwnConsR
			},
		},
		{
			apiUserStatus + h.MethodPut,
			func() {
				c.Cmd = set
				c.Adm = defaultDwnConsR
			},
		},
		{
			apiCheckUser + h.MethodGet,
			func() {
				c.Cmd = check
				c.Adm = defaultSessionIPM
			},
		},
		{
			apiUserInfo + h.MethodGet,
			func() {
				c.Cmd = get
				c.Adm = defaultUserDBInfo
			},
		},
	}
	if e == nil {
		exF(kf, pth+meth, func(d error) { e = d })
	}
	return
}

type srvHandler struct {
	serveHTTP h.HandlerFunc
	reqHnd    fh.RequestHandler
}

type srvConf struct {
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
	h.conf = append(h.sc.toStringMap)
	return
}

func (p *srvConf) toStringMap() (i interface{}) {
	i = map[string]interface{}{
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
