package pmproxy

import (
	"github.com/lamg/proxy"
	"time"
)

// connMng has the values for controlling how
// the proxy (github.com/lamg/proxy) handles the connection
type connMng struct {
	maxIdle int
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration

	// these are initialized at conf.go
	direct proxy.ContextDialer
	proxyF proxy.ParentProxyF
	ctxVal proxy.ContextValueF
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
