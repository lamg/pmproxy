package pmproxy

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
	Cmd     string
	AdmName string
}

func readAdmConn() (a *admConn, e error) {
	a = new(admConn)
	a.confs = append(a.confs, p.toStringMap)
	mp := viper.Get(proxyTr)
	e = a.fromStringMap(mp)
	// read ip matchers
	// read consumption restrictors
	// read rules
	// read admins
	// read logger
	// get searializers
	// initialize direct, proxyF, ctxVal
	//   admin
	//   confs
	a.proxyF, a.ctxVal = evalRules(rules)
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
