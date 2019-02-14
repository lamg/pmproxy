package pmproxy

import (
	"github.com/lamg/proxy"
	"time"
)

// connMng has the values for controlling how
// the proxy (github.com/lamg/proxy) handles the connection,
// and the values for controlling at runtime those values
type connMng struct {
	maxIdle int
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration
	direct  proxy.ContextDialer
	proxyF  proxy.ParentProxyF
	ctxVal  proxy.ContextValueF
}

type manager func(*cmd)
type managerKF func(*cmd) []kFunc

type cmd struct {
	Cmd        string
	Manager    string
	RemoteAddr string
	Secret     string
	bs         []byte
	e          error
}

func newConnMng(cf *conf) (a *connMng, e error) {
	// TODO initialize direct, proxyF, ctxVal

	iu := newIPUserS()
	ms, e := cf.matchers()

	a = new(connMng)
	cf.mappers = append(cf.mappers, a.toMap)
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

func (p *connMng) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:    proxyTr,
		maxIdleK: p.maxIdle,
		idleTK:   p.idleT,
		tlsHTK:   p.tlsHT,
		expCTK:   p.expCT,
	}
	return
}

func (p *connMng) fromMap(i interface{}) (e error) {
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
