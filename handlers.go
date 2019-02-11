package pmproxy

import (
	"bytes"
	"encoding/json"
	fh "github.com/valyala/fasthttp"
	h "net/http"
)

type handlerConf struct {
	sh   *srvHandler
	sc   *srvConf
	conf []func() interface{}
}

func newHnds(c *conf) (hs []*handlerConf,
	fs []func() interface{}, e error) {
	var sl []interface{}
	var ac *admConn
	fs := []func(){
		func() {
			sl, e = c.sliceE("srvConf")
		},
		func() {
			if len(sl) != 2 {
				e = fmt.Errorf("Need two servers, not %d", len(sl))
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
			ac, e = readAdmConn(c)
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

func readHnd(hcs []*handlerConf, ac *admConn, c *conf) {
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
			comp02 := c.böol("compatible0.2")
			staticFPath := c.strïng("staticFilesPath")
			if hcs[i].sc.fastOrStd {
				hcs[i].reqHnd = fastIface(ac, comp02, staticFPath)
			} else {
				hcs[i].serveHTTP = stdIface(ac, comp02, staticFPath)
			}
		}
	}
	forall(inf, len(hcs))
	return
}

func fastIface(ac *admConn, comp02 bool,
	staticFPath string) (hnd fh.RequestHandler) {
	fs := &fh.FS{
		Root: staticFPath,
	}
	fsHnd := fs.NewRequestHandler()
	hnd = func(ctx *fh.RequestCtx) {
		if comp02 {
			pth := string(ctx.Request.URI().Path)
			meth := string(ctx.Method)
			token := string(ctx.Request.Header.Peek("authHd"))
			if strings.HasPrefix(pth, "/api") {
				cmd, e = compatibleCmd(pth, meth, token)
			} else {
				// serve static files
				if pth == "/login" || pth == "/login/" {
					pth = ""
				}
				fsHnd(ctx)
				cmd = admCmd{
					Cmd: skip,
				}
			}
		}
		buff, cmd := new(bytes.Buffer), new(admCmd)
		var e error
		var bs []byte
		fs := []func(){
			func() { e = ctx.Request.BodyWriteTo(buff) },
			func() { e = json.NewDecoder(buff).Decode(cmd) },
			func() { bs, e = ac.admin(cmd) },
			func() {
				if bs != nil {
					ctx.Response.SetBody(bs)
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

func stdIface(ac *admConn, comp02 bool,
	staticFPath string) (hnd h.HandlerFunc) {
	hnd = func(w h.ResponseWriter, r *h.Request) {
		var cmd *admCmd
		var e error
		if comp02 {
			pth := r.URL.Path
			if strings.HasPrefix(pth, "/api") {
				cmd, e = compatibleCmd(pth, r.Method,
					r.Header.Get("authHd"))
			} else {
				if pth == "/login" || pth == "/login/" {
					pth = ""
				}
				// serve static
				h.ServeFile(w, r, path.Join(staticFPath, pth))
				cmd := &admCmd{
					Cmd: skip,
				}
			}
		} else {
			cmd = new(admCmd)
		}

		var e error
		var bs []byte
		fs := []func(){
			func() {
				e = json.NewDecoder(r.Body).Decode(cmd)
			},
			func() { bs, e = ac.admin(cmd) },
			func() {
				if bs != nil {
					_, e = w.Write(bs)
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

func compatibleCmd(pth, meth, rAddr, hd string) (c *admCmd,
	e error) {
	ip, _, e := net.SplitHostPort(rAddr)
	c = &admCmd{
		RemoteAddr: ip,
		Secret:     hd,
	}

	kf := []kFunc{
		{
			"/api/auth" + h.MethodPost,
			func() {
				c.Cmd = open
				c.Adm = "sm"
			},
		},
		{
			"/api/auth" + h.MethodDelete,
			func() {
				c.Cmd = clöse
				c.Adm = "sm"
			},
		},
		{
			"/api/userStatus" + h.MethodGet,
			func() {
				c.Cmd = get
				c.Adm = "dw"
			},
		},
		{
			"/api/userStatus" + h.MethodPut,
			func() {
				c.Cmd = set
				c.Adm = "dw"
			},
		},
		{
			"/api/checkUser" + h.MethodGet,
			func() {
				c.Cmd = check
				c.Adm = "sm"
			},
		},
		{
			"/api/userInfo" + h.MethodGet,
			func() {
				c.Cmd = get
				c.Adm = "userInfo"
				// User {
				// 	 "userName" string,
				// 		"name" string,
				// 		"isAdmin" bool,
				// 		"quotaGroup" uint64
				// }
			},
		},
	}
	if e == nil {
		exF(kf, pth+meth, func(d error) { e = d })
	}
	return
}

type srvHandler struct {
	serveHTTP h.HandleFunc
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

const (
	proxyOrIfaceK = "proxyOrIface"
	fastOrStdK    = "fastOrStd"
	readTimeoutK  = "readTimeout"
	writeTimeoutK = "writeTimeout"
	addrK         = "addr"
	certK         = "cert"
	keyK          = "key"
	maxConnIPK    = "maxConnIP"
	maxReqConnK   = "maxReqConn"
)

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
