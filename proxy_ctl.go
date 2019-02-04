package pmproxy

import (
	fh "github.com/valyala/fasthttp"
	"io"
	"net"
	h "net/http"
)

type handlerConf struct {
	sh *srvHandler
	sc *srvConf
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
	maxConnIP    int
	maxReqConn   int
}

type prxConf struct {
	direct  proxy.ContextDialer
	v       proxy.ContextValueF
	clock   func() time.Time
	parP    proxy.ParentProxyF
	maxIdle int
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration
}

func newHnds() (hs []*handlerConf, e error) {
	var sl []interface{}
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
			ib := func(i int) (b bool) {
				e = readPrxConf(hs[i].sc)
				b = e == nil
				return
			}
			trueForall(ib, len(hs))
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func readSrvConf(i interface{}) (h *handlerConf,
	e error) {
	h = &handlerConf{sc: new(srvConf)}
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			"proxyOrIface",
			func(i interface{}) {
				h.sc.proxyOrIface = boolE(i, fe)
			},
		},
		{
			"fastOrStd",
			func(i interface{}) {
				h.sc.fastOrStd = boolE(i, fe)
			},
		},
		{
			"readTimeout",
			func(i interface{}) {
				h.sc.readTimeout = durationE(i, fe)
			},
		},
		{
			"writeTimeout",
			func(i interface{}) {
				h.sc.writeTimeout = durationE(i, fe)
			},
		},
		{
			"addr",
			func(i interface{}) {
				h.sc.addr = stringE(i, fe)
			},
		},
		{
			"cert",
			func(i interface{}) {
				h.sc.certFl = stringE(i, fe)
			},
		},
		{
			"key",
			func(i interface{}) {
				h.sc.keyFl = stringE(i, fe)
			},
		},
		{
			"maxConnIP",
			func(i interface{}) {
				h.sc.maxConnIP = intE(i, fe)
			},
		},
		{
			"maxReqConn",
			func(i interface{}) {
				h.sc.maxReqConn = intE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func readHnd(hc *handlerConf) (e error) {
	if hc.sc.proxyOrIface {
		// consumers, matchers determine context values
		// dialer and proxy process context values
		if hc.sc.fastOrStd {

		}
	} else {
		// administration, and serializer are part of the
		// control interface, and also have consumers and
		// matchers

		// some consumer and matchers have common data
	}
	return
}

// ProxyCtl has the handlers for the HTTP servers
type proxyCtl struct {
	// contains the fields for initializing
	// github.com/lamg/proxy.Proxy
	PrxFls *SpecCtx
	adm    *globAdm
}

func newProxyCtl() (p *ProxyCtl, e error) {
	return
}

// serveHTTP is the handler that implements the
// administration interface to be served by an HTTP server
func (p *ProxyCtl) serveHTTP(w h.ResponseWriter,
	r *h.Request) {
	ips, _, e := net.SplitHostPort(r.RemoteAddr)
	var cmd *AdmCmd
	if e == nil {
		cmd = new(AdmCmd)
		e = Decode(r.Body, cmd)
	}
	var bs []byte
	if e == nil {
		r.Body.Close()
		cmd.RemoteIP = ips
		bs, e = p.adm.dispatch(cmd)
	}
	if e == nil {
		_, e = w.Write(bs)
	}
	if e != nil {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

func (p *ProxyCtl) persist(w io.Writer) (e error) {
	e = p.adm.persist(w)
	return
}

func (p *ProxyCtl) fastHandler(cxt *fh.RequestCtx) {
	return
}
