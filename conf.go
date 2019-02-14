package pmproxy

import (
	"context"
	"encoding/json"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"sync"
	"time"
	"url"
)

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

type conf struct {
	admins     []string
	iu         *ipUserS
	managerKFs *sync.Map
	matchers   *sync.Map
	consRs     *sync.Map
	mappers    *sync.Map
	userDBs    *sync.Map
	ipQuotas   *sync.Map
	lg         *logger
	rls        *rules
	cm         *connMng
}

func newConf(iu *ipUser) (c *conf, e error) {
	// read ip matchers
	// read user information provider
	// read consumption restrictors
	// read rules
	// read admins
	// read logger
	// get searializers (c.mappers)
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")
	viper.ReadInConfig()

	c = &conf{
		admins:     viper.GetStringSlice(adminsK),
		iu:         iu,
		managerKFs: new(sync.Map),
		matchers:   new(sync.Map),
		consRs:     new(sync.Map),
		mappers:    new(sync.Map),
		userDBs:    new(sync.Map),
		ipQuotas:   new(sync.Map),
	}

	fs := []func(){
		func() { e = c.initUserDBs() },
		func() { e = c.initSessionIPMs() },
		func() { e = c.initIPQuotas() },
		func() { e = c.initDwnConsRs() },
		func() { e = c.initUserInfos() },
		func() { e = c.initGroupIPMs() },
		func() { e = c.initLogger() },
		func() { e = c.initRules() },
		func() { e = c.initConnMng() },
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *conf) initUserDBs() (e error) {
	// def.(maps in c)
	fm := func(i interface{}) {
		udb := new(userDB)
		e = udb.fromMap(i)
		if e == nil {
			c.managerKFs.Store(udb.name, udb.managerKF)
			c.mappers.Store(udb.name, udb.toMap)
			c.userDBs.Store(udb.name, udb)
		}
	}
	c.sliceMap(userDBK, fm, func() bool { return e == nil })
	return
}

func (c *conf) initSessionIPMs() (e error) {
	// c.initUsrDBs() /\ def.(maps in c)
	fm := func(i interface{}) {
		sm := &sessionIPM{
			ipUser: c.iu,
		}
		e = sm.fromMap(i)
		if e == nil {
			sm.auth = c.authenticator
			c.managerKFs.Store(sm.name, sm.managerKF)
			c.matchers.Store(sm.name, sm.match)
			c.mappers.Store(sm.name, sm.toMap)
		}
	}
	e = sliceMap(sessionIPMK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) authenticator(name string) (a auth,
	ok bool) {
	v, ok := c.userDBs.Load(name)
	if ok {
		a = v.(*userDB).auth
	}
	return
}

func (c *conf) initIPQuotas() (e error) {
	// def.(maps in c, c.iu) /\ c.initUserDBs()
	fm := func(i interface{}) {
		ipq := new(ipQuotaS)
		e = ipq.fromMap(i)
		if e == nil {
			ipq.ipGroup.ipUser = c.iu.get
			ipq.ipGroup.userGroup = c.userGroup
			c.managerKFs.Store(ipq.name, ipq.managerKF)
			c.ipQuotas.Store(ipq.name, ipq.get)
			c.mappers.Store(ipq.name, ipq.toMap)
		}
	}
	c.sliceMap(ipQuotaK, fm, func() bool { return e == nil })
	return
}

func (c *conf) initDwnConsRs() (e error) {
	// c.initIPQuotas() /\ def.(maps in c)
	dws := make([]*dwnConsR, 0)
	fm := func(i interface{}) {
		dw := new(dwnConsR)
		e = dw.fromMap(i)
		if e == nil {
			v, ok := c.ipQuotas.Load(dw.ipQuotaN)
			if ok {
				dw.ipq = v.(*ipQuotaS).get
			}
			c.managerKFs.Store(dw.name, dw.managerKF)
			c.consRs.Store(dw.name, dw.consR())
			c.mappers.Store(dw.name, dw.toMap)
		}
	}
	e = sliceMap(dwnConsRK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) userGroup(name string) (g userGroup,
	ok bool) {
	v, ok := c.userDBs.Load(name)
	if ok {
		g = v.(*userDB).userGroup
	}
	return
}

func (c *conf) initUserInfos() (e error) {
	// notice that there are several userDB
	// forall of them a userInfo should exist
	// for each userDB, for each ipQuota with the same
	// userDB
	// def.(c.admins, c.iu, maps in c) /\ c.initUserDBs()
	isAdm := func(user string) (v bool) {
		v, _ = bLnSrch(func(i int) bool {
			return c.admins[i] == user
		},
			len(c.admins),
		)
	}
	c.ipQuotas.Range(func(k, v interface{}) (ok bool) {
		udbName := k.(string)
		uv, ok := c.userDBs.Load(udbName)
		if ok {
			udb := uv.(*userDB)
			ui := &userInfo{
				iu:        c.iu,
				userName:  c.userName,
				quota:     v.(ipQuota),
				userIsAdm: isAdm,
			}
			c.managerKFs.Store(udbName+infoK, ui.managerKF)
		}
		ok = true
		return
	})
	return
}

func (c *conf) initGroupIPMs() (e error) {
	// def.(maps in c, c.iu) /\ c.initUserDBs()
	fm := func(i interface{}) {
		gipm := new(groupIPM)
		e = gipm.fromMap(i)
		if e == nil {
			gipm.ipGroup.ipUser = c.iu
			gipm.ipGroup.userGroup = c.userGroup
			c.managerKFs.Store(gipm.name, gipm.managerKF)
			c.mappers.Store(gipm.name, gipm.toMap)
			c.matchers.Store(gipm.name, gipm.match)
		}
	}
	c.sliceMap(groupIPMK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK))
	return
}

func (c *conf) initRules() (e error) {
	// c.initSessionIPMs() /\ c.initGroupIPMs()
	// /\ c.initDwnConsRs()
	v := viper.Get(rulesK)
	c.rls = new(rules)
	e = c.rls.fromMap(v)
	c.managerKFs.Store(rulesK, c.rls.managerKF)
	// TODO
	// set matchers and consRs to rules
	// add rules.manager to c.managerKFs
	return
}

func (c *conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v := viper.Get(connMngK)
	e = c.cm.fromMap(v)
	c.cm.direct = newDialer(
		func(name string) (cr *consR, ok bool) {
			v, ok := c.consRs.Load(name)
			if ok {
				cr = v.(*consR)
			}
			return
		},
		c.lg,
	)
	c.cm.ctxVal = func(ctx context.Context, meth, ürl, addr,
		t time.Time) (nctx context.Context) {
		spec := c.rules.match(meth, ürl, addr, t)
		nctx = context.WithValue(ctx, specK, &specV{spec: spec})
		return
	}
	c.cm.proxyF = func(meth, ürl, addr string,
		t time.Time) (r *url.URL, e error) {
		spec := c.rules.match(meth, ürl, addr, t)
		r = spec.ProxyURL
		return
	}
	c.mappers.Store(connMngK, c.cm.toMap)
	return
}

func (c *conf) manager(m *cmd) {
	v, ok := c.managerKFs.Load(m.Manager)
	var kf []kFunc
	if ok {
		kf = v.(managerKF)(cmd)
		kf = append(kf,
			kFunc{skip, func() {}},
			kFunc{
				showAll,
				func() {
					mngs := make([]string, 0)
					c.managerKFs.Range(
						func(k, v interface{}) (ok bool) {
							mngs = append(mngs, k.(string))
							ok = true
							return
						},
					)
					cmd.bs, cmd.e = json.Marshal(&mngs)
				},
			},
		)
	}
	exF(kf, c.Cmd, func(d error) { m.e = d })
	return
}

func (c *conf) get(key string) (v interface{}) {
	v = viper.Get(key)
	return
}

func (c *conf) sliceE(key string) (sl []interface{},
	e error) {
	sl, e = cast.ToSliceE(c.get(key))
	return
}

func (c *conf) böol(key string) (b bool) {
	b = viper.GetBool(key)
	return
}

func (c *conf) strïng(key string) (s string) {
	s = viper.GetString(key)
	return
}

func (c *conf) configPath(file string) (fpath string) {
	cfl := viper.ConfigFileUsed()
	fpath = path.Join(path.Dir(cfl), file)
	return
}

func (c *conf) sliceMap(key string, fm func(interface{}),
	bf func() bool) (e error) {
	vs, e := c.sliceE(key)
	if e == nil {
		inf := func(i int) (b bool) {
			fm(vs[i])
			b = bf()
			return
		}
		trueForall(inf, len(vs))
	}
	return
}
