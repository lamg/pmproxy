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

func newHnds() (hs []*handlerConf,
	fs []func() interface{}, e error) {
	var sl []interface{}
	var ac *admConn
	fs := []func(){
		func() {
			sl, e = cast.ToSliceE(viper.Get("srvConf"))
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
			ac, e = readAdmConn()
		},
		func() {
			readHnd(hs, ac)
			forall(func(i int) {
				fs = append(fs, hs[i].sc.toStringMap)
			}, len(hs))
			fs = append(fs, ac.confs...)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func readHnd(hcs []*handlerConf, ac *admConn) {
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
		if hcs[i].sc.fastOrStd {
			hcs[i].reqHnd = func(ctx *fh.RequestCtx) {
				buff, cmd := new(bytes.Buffer), new(admCmd)
				var e error
				var bs []byte
				fs := []func(){
					func() { e = ctx.Request.BodyWriteTo(buff) },
					func() { e = json.NewDecoder(buff).Decode(cmd) },
					func() { bs, e = ac.admin(cmd) },
					func() { ctx.Response.SetBody(bs) },
				}
				ok := trueFF(fs, func() bool { return e == nil })
				if !ok {
					ctx.Response.SetStatusCode(h.StatusBadRequest)
					ctx.Response.SetBodyString(e.Error())
				}
			}
		} else {
			hcs[i].serveHTTP = func(w h.ResponseWriter,
				r *h.Request) {
				cmd := new(admCmd)
				var e error
				var bs []byte
				fs := []func(){
					func() {
						e = json.NewDecoder(r.Body).Decode(cmd)
					},
					func() { bs, e = ac.admin(cmd) },
					func() { _, e = w.Write(bs) },
				}
				ok := trueFF(fs, func() bool { return e == nil })
				if !ok {
					h.Error(w, e.Error())
				}
			}
		}
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
