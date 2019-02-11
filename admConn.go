package pmproxy

import (
	"github.com/lamg/proxy"
	"time"
)

// admConn has the values for controlling how
// the proxy (github.com/lamg/proxy) handles the connection,
// and the values for controlling at runtime those values
type admConn struct {
	maxIdle int
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration
	direct  proxy.ContextDialer
	proxyF  proxy.ParentProxyF
	ctxVal  proxy.ContextValueF
	admin   admin
	confs   []func() interface{}
}

type admin func(*admCmd) ([]byte, error)

type admCmd struct {
	Cmd        string
	Adm        string
	RemoteAddr string
	Secret     string
}

func readAdmConn(cf *conf) (a *admConn, e error) {
	// read ip matchers
	// read user information provider
	// read consumption restrictors
	// read rules
	// read admins
	// read logger
	// get searializers
	// initialize direct, proxyF, ctxVal
	//   admin
	//   confs

	iu := newIPUserS()
	ms, e := cf.matchers()

	a = new(admConn)
	a.admin = cf.admin
	a.confs = append(a.confs, p.toStringMap)
	mp := viper.Get(proxyTr)
	e = a.fromStringMap(mp)
	rls, e := readRules(c)
	a.proxyF, a.ctxVal = rls.evaluators(ms)

	consR, e := readConsR(iu)
	consRF := func(name string) (c *consR, ok bool) {
		v, ok := consR.Load(name)
		if ok {
			c = v.(*consR)
		}
		return
	}
	lg, e := readLogger(iu.get)
	a.direct, e = newDialer(consR, lg)
	return
}

const (
	proxyTr  = "proxyTransport"
	maxIdleK = "maxIdle"
	idleTK   = "idleT"
	tlsHTK   = "tlsHT"
	expCTK   = "expCT"
)

func (p *admConn) toStringMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:    proxyTr,
		maxIdleK: p.maxIdle,
		idleTK:   p.idleT,
		tlsHTK:   p.tlsHT,
		expCTK:   p.expCT,
	}
	return
}

func (p *admConn) fromStringMap(i interface{}) (e error) {
	fe := func(d error) { d = e }
	kf := []kFuncI{
		{
			maxIdleK,
			func(i interface{}) {
				p.maxIdle = intE(i, fe)
			},
		},
		{
			idleTK,
			func(i interface{}) {
				p.idleT = durationE(i, fe)
			},
		},
		{
			tlsHTK,
			func(i interface{}) {
				p.tlsHT = durationE(i, fe)
			},
		},
		{
			expCTK,
			func(i interface{}) {
				p.expCT = durationE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
}
